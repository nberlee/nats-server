// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skip_mqtt_tests

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// mqttV5ConnInfo describes an MQTT 5.0 CONNECT to craft. props/willProps are
// raw, already-encoded properties bodies (without the leading length varint);
// nil means an empty properties block.
type mqttV5ConnInfo struct {
	clientID   string
	cleanStart bool
	keepAlive  uint16
	props      []byte
	will       *mqttWill
	willProps  []byte
	user       string
	pass       string
}

func mqttV5CreateConnect(ci *mqttV5ConnInfo) []byte {
	flags := byte(0)
	if ci.cleanStart {
		flags |= mqttConnFlagCleanSession
	}
	if ci.will != nil {
		flags |= mqttConnFlagWillFlag | (ci.will.qos << 3)
		if ci.will.retain {
			flags |= mqttConnFlagWillRetain
		}
	}
	if ci.user != _EMPTY_ {
		flags |= mqttConnFlagUsernameFlag
	}
	if ci.pass != _EMPTY_ {
		flags |= mqttConnFlagPasswordFlag
	}

	vh := newMQTTWriter(0)
	vh.WriteString(string(mqttProtoName))
	vh.WriteByte(mqttProtoLevel5)
	vh.WriteByte(flags)
	vh.WriteUint16(ci.keepAlive)
	vh.WriteVarInt(len(ci.props))
	vh.Write(ci.props)
	vh.WriteString(ci.clientID)
	if ci.will != nil {
		vh.WriteVarInt(len(ci.willProps))
		vh.Write(ci.willProps)
		vh.WriteBytes(ci.will.topic)
		vh.WriteBytes(ci.will.message)
	}
	if ci.user != _EMPTY_ {
		vh.WriteString(ci.user)
	}
	if ci.pass != _EMPTY_ {
		vh.WriteBytes([]byte(ci.pass))
	}

	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketConnect)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	return w.Bytes()
}

// testMQTTConnectV5 dials, sends a v5 CONNECT and returns the connection and a
// reader positioned to read the CONNACK.
func testMQTTConnectV5(t testing.TB, ci *mqttV5ConnInfo, host string, port int) (net.Conn, *mqttReader) {
	t.Helper()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Error dialing: %v", err)
	}
	if _, err := testMQTTWrite(c, mqttV5CreateConnect(ci)); err != nil {
		t.Fatalf("Error writing connect: %v", err)
	}
	mr := &mqttReader{reader: c}
	return c, mr
}

// testMQTTReadConnAckV5 reads and validates an MQTT 5.0 CONNACK, returning the
// session-present flag, the reason code and the parsed properties.
func testMQTTReadConnAckV5(t testing.TB, r *mqttReader) (bool, byte, *mqttProperties) {
	t.Helper()
	b, pl := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketConnectAck {
		t.Fatalf("Expected CONNACK (%x), got %x", mqttPacketConnectAck, pt)
	}
	start := r.pos
	caf, err := r.readByte("connack flags")
	if err != nil {
		t.Fatalf("Error reading connack flags: %v", err)
	}
	if caf&0xfe != 0 {
		t.Fatalf("CONNACK flag bits 7-1 must be 0, got %x", caf)
	}
	reason, err := r.readByte("reason code")
	if err != nil {
		t.Fatalf("Error reading reason code: %v", err)
	}
	props, err := r.readProperties(mqttPacketConnectAck)
	if err != nil {
		t.Fatalf("Error reading CONNACK properties: %v", err)
	}
	if consumed := r.pos - start; consumed != pl {
		t.Fatalf("CONNACK remaining length is %d but consumed %d bytes", pl, consumed)
	}
	return caf&1 == 1, reason, props
}

// ---- SUBSCRIBE / PUBLISH / UNSUBSCRIBE v5 crafting ----

type mqttV5SubFilter struct {
	topic string
	opts  byte // subscription options byte (QoS in bits 0-1)
}

func testMQTTSubV5(t testing.TB, c net.Conn, r *mqttReader, pi uint16, filters []mqttV5SubFilter) []byte {
	t.Helper()
	return testMQTTSubV5Props(t, c, r, pi, nil, filters)
}

// testMQTTSubV5Props sends a SUBSCRIBE whose variable header carries the given
// raw properties block (length prefix + body); a nil props block is encoded as a
// single 0 length byte (empty properties).
func testMQTTSubV5Props(t testing.TB, c net.Conn, r *mqttReader, pi uint16, props []byte, filters []mqttV5SubFilter) []byte {
	t.Helper()
	vh := newMQTTWriter(0)
	vh.WriteUint16(pi)
	if len(props) > 0 {
		vh.Write(props)
	} else {
		vh.WriteVarInt(0) // empty properties
	}
	for _, f := range filters {
		vh.WriteBytes([]byte(f.topic))
		vh.WriteByte(f.opts)
	}
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketSub | mqttSubscribeFlags)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing SUBSCRIBE: %v", err)
	}

	// Read SUBACK: PI + properties + one reason code per filter.
	b, pl := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketSubAck {
		t.Fatalf("Expected SUBACK (%x), got %x", mqttPacketSubAck, pt)
	}
	start := r.pos
	rpi, err := r.readUint16("suback pi")
	if err != nil || rpi != pi {
		t.Fatalf("Expected SUBACK pi=%v, got %v (err=%v)", pi, rpi, err)
	}
	if _, err := r.readProperties(mqttPacketSubAck); err != nil {
		t.Fatalf("Error reading SUBACK properties: %v", err)
	}
	codes := make([]byte, 0, len(filters))
	for r.pos-start < pl {
		rc, err := r.readByte("suback reason code")
		if err != nil {
			t.Fatalf("Error reading SUBACK reason code: %v", err)
		}
		codes = append(codes, rc)
	}
	if len(codes) != len(filters) {
		t.Fatalf("Expected %d SUBACK reason codes, got %d", len(filters), len(codes))
	}
	return codes
}

func testMQTTUnsubV5(t testing.TB, c net.Conn, r *mqttReader, pi uint16, topics []string) []byte {
	t.Helper()
	vh := newMQTTWriter(0)
	vh.WriteUint16(pi)
	vh.WriteVarInt(0) // empty properties
	for _, tp := range topics {
		vh.WriteBytes([]byte(tp))
	}
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketUnsub | mqttUnsubscribeFlags)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing UNSUBSCRIBE: %v", err)
	}

	b, pl := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketUnsubAck {
		t.Fatalf("Expected UNSUBACK (%x), got %x", mqttPacketUnsubAck, pt)
	}
	start := r.pos
	rpi, err := r.readUint16("unsuback pi")
	if err != nil || rpi != pi {
		t.Fatalf("Expected UNSUBACK pi=%v, got %v (err=%v)", pi, rpi, err)
	}
	if _, err := r.readProperties(mqttPacketUnsubAck); err != nil {
		t.Fatalf("Error reading UNSUBACK properties: %v", err)
	}
	codes := make([]byte, 0, len(topics))
	for r.pos-start < pl {
		rc, err := r.readByte("unsuback reason code")
		if err != nil {
			t.Fatalf("Error reading UNSUBACK reason code: %v", err)
		}
		codes = append(codes, rc)
	}
	return codes
}

func testMQTTPublishV5(t testing.TB, c net.Conn, qos byte, pi uint16, topic string, payload []byte) {
	t.Helper()
	flags := qos << 1
	vh := newMQTTWriter(0)
	vh.WriteBytes([]byte(topic))
	if qos > 0 {
		vh.WriteUint16(pi)
	}
	vh.WriteVarInt(0) // empty properties
	vh.Write(payload)
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketPub | flags)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing PUBLISH: %v", err)
	}
}

// testMQTTPubV5SelfEcho publishes a QoS1 message on a topic the same connection
// is subscribed to without No Local, then consumes both the PUBACK for the
// publish and the echoed PUBLISH (acking it) in whichever order they arrive: the
// server may begin onward delivery before it enqueues the PUBACK, so the order
// is not deterministic. It asserts the echo's topic and payload.
func testMQTTPubV5SelfEcho(t testing.TB, c net.Conn, r *mqttReader, pi uint16, topic string, payload []byte) {
	t.Helper()
	vh := newMQTTWriter(0)
	vh.WriteBytes([]byte(topic))
	vh.WriteUint16(pi)
	vh.WriteVarInt(0) // empty properties
	vh.Write(payload)
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketPub | (1 << 1))
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing PUBLISH: %v", err)
	}

	var gotAck, gotEcho bool
	for !(gotAck && gotEcho) {
		b, pl := testMQTTReadPacket(t, r)
		start := r.pos
		switch b & mqttPacketMask {
		case mqttPacketPubAck:
			if gotAck {
				t.Fatal("received two PUBACKs")
			}
			rpi, err := r.readUint16("puback pi")
			if err != nil || rpi != pi {
				t.Fatalf("Expected PUBACK pi=%v, got %v (err=%v)", pi, rpi, err)
			}
			gotAck = true
		case mqttPacketPub:
			if gotEcho {
				t.Fatal("received two PUBLISHes")
			}
			etopic, err := r.readBytes("topic", false)
			if err != nil {
				t.Fatalf("Error reading topic: %v", err)
			}
			epi, err := r.readUint16("pi")
			if err != nil {
				t.Fatalf("Error reading pi: %v", err)
			}
			if _, err := r.readProperties(mqttPropsContextPubOut); err != nil {
				t.Fatalf("Error reading PUBLISH properties: %v", err)
			}
			egot := r.buf[r.pos : start+pl]
			if string(etopic) != topic || string(egot) != string(payload) {
				t.Fatalf("Expected echo %q=%q, got %q=%q", topic, payload, etopic, egot)
			}
			pa := [4]byte{mqttPacketPubAck, 0x2, byte(epi >> 8), byte(epi)}
			if _, err := testMQTTWrite(c, pa[:]); err != nil {
				t.Fatalf("Error writing PUBACK: %v", err)
			}
			gotEcho = true
		default:
			t.Fatalf("Expected PUBACK or PUBLISH, got %x", b&mqttPacketMask)
		}
		// Consume the whole packet so the reader stays aligned for the next one.
		r.pos = start + pl
	}
}

// testMQTTReadPubCheckRetainV5 reads a delivered v5 PUBLISH, validates its
// topic, payload and RETAIN flag, and acks a QoS1 delivery.
func testMQTTReadPubCheckRetainV5(t testing.TB, c net.Conn, r *mqttReader, expTopic string, expPayload []byte, expRetain bool) {
	t.Helper()
	b, pl := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketPub {
		t.Fatalf("Expected PUBLISH (%x), got %x", mqttPacketPub, pt)
	}
	if got := b&mqttPubFlagRetain != 0; got != expRetain {
		t.Fatalf("Expected RETAIN=%v for %q, got %v", expRetain, expTopic, got)
	}
	start := r.pos
	qos := mqttGetQoS(b & mqttPacketFlagMask)
	topic, err := r.readBytes("topic", false)
	if err != nil {
		t.Fatalf("Error reading topic: %v", err)
	}
	if string(topic) != expTopic {
		t.Fatalf("Expected topic %q, got %q", expTopic, topic)
	}
	var pi uint16
	if qos > 0 {
		if pi, err = r.readUint16("pi"); err != nil {
			t.Fatalf("Error reading pi: %v", err)
		}
	}
	if _, err := r.readProperties(mqttPropsContextPubOut); err != nil {
		t.Fatalf("Error reading PUBLISH properties: %v", err)
	}
	got := r.buf[r.pos : start+pl]
	if string(got) != string(expPayload) {
		t.Fatalf("Expected payload %q, got %q", expPayload, got)
	}
	r.pos = start + pl
	if qos == 1 {
		pa := [4]byte{mqttPacketPubAck, 0x2, byte(pi >> 8), byte(pi)}
		if _, err := testMQTTWrite(c, pa[:]); err != nil {
			t.Fatalf("Error writing PUBACK: %v", err)
		}
	}
}

// testMQTTReadPublishV5 reads a PUBLISH delivered by the server to a v5 client
// and validates the topic and payload. It returns the QoS and packet id.
func testMQTTReadPublishV5(t testing.TB, r *mqttReader, expTopic string, expPayload []byte) (byte, uint16) {
	t.Helper()
	b, pl := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketPub {
		t.Fatalf("Expected PUBLISH (%x), got %x", mqttPacketPub, pt)
	}
	start := r.pos
	qos := mqttGetQoS(b & mqttPacketFlagMask)
	topic, err := r.readBytes("topic", false)
	if err != nil {
		t.Fatalf("Error reading topic: %v", err)
	}
	if string(topic) != expTopic {
		t.Fatalf("Expected topic %q, got %q", expTopic, topic)
	}
	var pi uint16
	if qos > 0 {
		if pi, err = r.readUint16("pi"); err != nil {
			t.Fatalf("Error reading pi: %v", err)
		}
	}
	// v5: a properties block precedes the payload.
	if _, err := r.readProperties(mqttPropsContextPubOut); err != nil {
		t.Fatalf("Error reading PUBLISH properties: %v", err)
	}
	payloadLen := pl - (r.pos - start)
	if payloadLen < 0 || r.pos+payloadLen > len(r.buf) {
		t.Fatalf("Invalid payload length %d", payloadLen)
	}
	got := r.buf[r.pos : r.pos+payloadLen]
	r.pos += payloadLen
	if string(got) != string(expPayload) {
		t.Fatalf("Expected payload %q, got %q", expPayload, got)
	}
	return qos, pi
}

func testMQTTReadPubAck(t testing.TB, r *mqttReader, expPI uint16) {
	t.Helper()
	b, _ := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketPubAck {
		t.Fatalf("Expected PUBACK (%x), got %x", mqttPacketPubAck, pt)
	}
	pi, err := r.readUint16("puback pi")
	if err != nil || pi != expPI {
		t.Fatalf("Expected PUBACK pi=%v, got %v (err=%v)", expPI, pi, err)
	}
}

// ---- Tests ----

// testMQTTDefaultOptionsV5 returns default MQTT options with MQTT 5.0 enabled.
// v5 is opt-in (disabled by default while it is being completed), so every test
// that connects with protocol level 5 must enable it explicitly.
func testMQTTDefaultOptionsV5() *Options {
	o := testMQTTDefaultOptions()
	o.MQTT.MaxProtocolVersion = 5
	return o
}

// By default (no MaxProtocolVersion set) the server must accept only 3.1.1 and
// reject a v5 CONNECT with reason 0x84, so clients fall back to 3.1.1.
func TestMQTTv5DisabledByDefault(t *testing.T) {
	o := testMQTTDefaultOptions()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "v5off", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	_, reason, _ := testMQTTReadConnAckV5(t, r)
	if reason != mqttReasonUnsupportedProtocolVersion {
		t.Fatalf("Expected v5 to be rejected with 0x%x by default, got 0x%x", mqttReasonUnsupportedProtocolVersion, reason)
	}

	// A 3.1.1 client connects normally.
	c2, r2 := testMQTTConnect(t, &mqttConnInfo{clientID: "v311ok", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer c2.Close()
	testMQTTCheckConnAck(t, r2, mqttConnAckRCConnectionAccepted, false)
}

func TestMQTTv5ConnectAndCapabilities(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "v5conn", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()

	sp, reason, props := testMQTTReadConnAckV5(t, r)
	if sp {
		t.Fatalf("Did not expect session present on a clean start")
	}
	if reason != mqttReasonSuccess {
		t.Fatalf("Expected success reason 0x%x, got 0x%x", mqttReasonSuccess, reason)
	}
	if props == nil {
		t.Fatal("Expected CONNACK properties")
	}
	// Maximum QoS must be absent: a value of 2 is illegal in this property, and
	// absence signals full QoS 2 support. Spec5 [3.2.2.3.4].
	if props.present[mqttPropMaxQoS] {
		t.Fatalf("Maximum QoS property must be omitted (absence => QoS 2), got %v", props.maxQoS)
	}
	// Retain / wildcard subscriptions are supported and advertised by absence
	// (their default is "available"), so they must not be sent explicitly.
	if props.present[mqttPropRetainAvailable] {
		t.Fatalf("Retain Available should be omitted (supported by default)")
	}
	if props.present[mqttPropWildcardSubAvailable] {
		t.Fatalf("Wildcard Subscription Available should be omitted (supported by default)")
	}
	// Shared subscriptions are not implemented, so must be advertised as off
	// (their default is "available", so it must be sent explicitly as 0).
	if !props.present[mqttPropSharedSubAvailable] || props.sharedSubAvail != 0 {
		t.Fatalf("Expected Shared Subscription Available=0")
	}
	// Subscription identifiers are supported, so the property must be omitted
	// (absent => available).
	if props.present[mqttPropSubIDAvailable] {
		t.Fatalf("Subscription Identifier Available should be omitted (supported)")
	}
}

func TestMQTTv5AssignedClientID(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// Empty client ID with clean start: server assigns one and echoes it.
	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()

	_, reason, props := testMQTTReadConnAckV5(t, r)
	if reason != mqttReasonSuccess {
		t.Fatalf("Expected success, got 0x%x", reason)
	}
	if props == nil || props.assignedClientID == _EMPTY_ {
		t.Fatalf("Expected an assigned client identifier, got %+v", props)
	}
}

func TestMQTTv5MalformedConnectProperties(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	userProp := func(k, v string) []byte {
		w := newMQTTWriter(0)
		w.WriteByte(mqttPropUserProperty)
		w.WriteString(k)
		w.WriteBytes([]byte(v))
		return w.Bytes()
	}

	for _, test := range []struct {
		name   string
		props  []byte
		reason byte
	}{
		{
			// A property not allowed in CONNECT (0x24 Maximum QoS is CONNACK-only)
			// is a Protocol Error. Spec5 [3.1.4.1].
			"property not allowed", []byte{mqttPropMaxQoS, 0x00}, mqttReasonProtocolError,
		},
		{
			// Spec5 [3.1.2.11.7]: Request Problem Information other than 0/1.
			"request problem info out of range", []byte{mqttPropRequestProblemInfo, 0x05}, mqttReasonProtocolError,
		},
		{
			// Spec5 [3.1.2.11.6]: Request Response Information other than 0/1.
			"request response info out of range", []byte{mqttPropRequestResponseInfo, 0x02}, mqttReasonProtocolError,
		},
		{
			// Spec5 [3.1.2.11.10]: Authentication Data without Authentication Method.
			"auth data without method", []byte{mqttPropAuthData, 0x00, 0x01, 0xAB}, mqttReasonProtocolError,
		},
		{
			// Spec5 [MQTT-1.5.4-1]: ill-formed UTF-8 in a property string is a
			// Malformed Packet.
			"invalid utf8 user property", userProp("k", "\xff\xfe"), mqttReasonMalformedPacket,
		},
		{
			// Spec5 [MQTT-1.5.4-2]: U+0000 in a property string is a Malformed Packet.
			"null in user property", userProp("k", "a\x00b"), mqttReasonMalformedPacket,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "bad", cleanStart: true, props: test.props}, o.MQTT.Host, o.MQTT.Port)
			defer c.Close()

			_, reason, _ := testMQTTReadConnAckV5(t, r)
			if reason != test.reason {
				t.Fatalf("Expected reason 0x%x, got 0x%x", test.reason, reason)
			}
		})
	}
}

func TestMQTTv5MalformedConnectConnAck(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// A structurally malformed CONNECT (Password Flag set but the payload is
	// truncated before the password bytes) must draw a CONNACK with reason 0x81
	// Malformed Packet before the close, not a bare close. [MQTT-3.1.2-19].
	vh := newMQTTWriter(0)
	vh.WriteString(string(mqttProtoName))
	vh.WriteByte(mqttProtoLevel5)
	vh.WriteByte(mqttConnFlagUsernameFlag | mqttConnFlagPasswordFlag)
	vh.WriteUint16(0) // keep alive
	vh.WriteVarInt(0) // empty properties
	vh.WriteString("mal")
	vh.WriteString("user")
	// Password flag is set but no password bytes follow: the parser runs off
	// the end of the packet.
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketConnect)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())

	addr := net.JoinHostPort(o.MQTT.Host, fmt.Sprintf("%d", o.MQTT.Port))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Error dialing: %v", err)
	}
	defer c.Close()
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing connect: %v", err)
	}

	_, reason, _ := testMQTTReadConnAckV5(t, &mqttReader{reader: c})
	if reason != mqttReasonMalformedPacket {
		t.Fatalf("Expected reason 0x%x (malformed packet), got 0x%x", mqttReasonMalformedPacket, reason)
	}
}

func TestMQTTv5AuthMethodRejected(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// Enhanced authentication is not supported: requesting an Authentication
	// Method must be rejected with reason 0x8c (Bad authentication method).
	props := newMQTTWriter(0)
	props.WriteByte(mqttPropAuthMethod)
	props.WriteString("SCRAM-SHA-1")
	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "auth", cleanStart: true, props: props.Bytes()}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()

	_, reason, _ := testMQTTReadConnAckV5(t, r)
	if reason != mqttReasonBadAuthMethod {
		t.Fatalf("Expected reason 0x%x (bad auth method), got 0x%x", mqttReasonBadAuthMethod, reason)
	}
}

func TestMQTTv5ConnectedProtocolErrorDisconnectReason(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "pe", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)

	// A connected client sends a PUBLISH whose Response Topic property contains
	// a wildcard (a Protocol Error, Spec5 [3.3.2.3.5]). The server must close
	// with a DISCONNECT carrying reason 0x82, not the generic 0x80.
	props := newMQTTWriter(0)
	props.WriteByte(mqttPropResponseTopic)
	props.WriteString("a/+/b")
	vh := newMQTTWriter(0)
	vh.WriteString("foo")
	vh.WriteVarInt(props.Len())
	vh.Write(props.Bytes())
	vh.Write([]byte("msg"))
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketPub)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing PUBLISH: %v", err)
	}

	b, _ := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketDisconnect {
		t.Fatalf("Expected DISCONNECT (%x), got %x", mqttPacketDisconnect, pt)
	}
	reason, err := r.readByte("disconnect reason")
	if err != nil {
		t.Fatalf("Error reading disconnect reason: %v", err)
	}
	if reason != mqttReasonProtocolError {
		t.Fatalf("Expected reason 0x%x (protocol error), got 0x%x", mqttReasonProtocolError, reason)
	}
}

func TestMQTTv5PubRecFailureSkipsPubRel(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// Subscriber with a QoS2 subscription.
	subc, subr := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer subc.Close()
	testMQTTReadConnAckV5(t, subr)
	testMQTTSubV5(t, subc, subr, 1, []mqttV5SubFilter{{topic: "foo", opts: 2}})
	testMQTTFlush(t, subc, nil, subr)

	// Publisher (3.1.1, so testMQTTPublish's framing matches) sends a QoS2 message.
	pubc, pubr := testMQTTConnect(t, &mqttConnInfo{clientID: "pub", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer pubc.Close()
	testMQTTCheckConnAck(t, pubr, mqttConnAckRCConnectionAccepted, false)
	testMQTTPublish(t, pubc, pubr, 2, false, false, "foo", 1, []byte("msg"))

	// Subscriber receives the PUBLISH at QoS2 but rejects it with a PUBREC
	// carrying a failure reason (0x80). Per Spec5 [4.3.3] the server must NOT
	// respond with a PUBREL.
	qos, pi := testMQTTReadPublishV5(t, subr, "foo", []byte("msg"))
	if qos != 2 {
		t.Fatalf("Expected QoS2 delivery, got %d", qos)
	}
	if _, err := testMQTTWrite(subc, []byte{mqttPacketPubRec, 3, byte(pi >> 8), byte(pi), 0x80}); err != nil {
		t.Fatalf("Error writing PUBREC: %v", err)
	}
	testMQTTExpectNothing(t, subr)
}

func TestMQTTv5MaxProtocolVersionCap(t *testing.T) {
	o := testMQTTDefaultOptions()
	o.MQTT.MaxProtocolVersion = 4 // restrict to 3.1.1
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "capped", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()

	_, reason, _ := testMQTTReadConnAckV5(t, r)
	if reason != mqttReasonUnsupportedProtocolVersion {
		t.Fatalf("Expected reason 0x%x (unsupported protocol version), got 0x%x", mqttReasonUnsupportedProtocolVersion, reason)
	}

	// A 3.1.1 client must still connect on the same capped server.
	c2, r2 := testMQTTConnect(t, &mqttConnInfo{clientID: "v311", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer c2.Close()
	testMQTTCheckConnAck(t, r2, mqttConnAckRCConnectionAccepted, false)
}

func TestMQTTv5PubSubQoS1(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// Subscriber connects v5 and subscribes QoS1.
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "v5sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	codes := testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "foo/bar", opts: 1}})
	if len(codes) != 1 || codes[0] != mqttReasonGrantedQoS1 {
		t.Fatalf("Expected granted QoS1 (0x%x), got %v", mqttReasonGrantedQoS1, codes)
	}

	// Publisher connects v5 and publishes QoS1.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "v5pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPublishV5(t, cp, 1, 100, "foo/bar", []byte("hello-v5"))
	testMQTTReadPubAck(t, rp, 100)

	// Subscriber receives the delivered PUBLISH (v5 framing with properties).
	qos, pi := testMQTTReadPublishV5(t, rs, "foo/bar", []byte("hello-v5"))
	if qos != 1 {
		t.Fatalf("Expected delivered QoS1, got %v", qos)
	}
	// Ack it (PUBACK, 2-byte form is valid in v5).
	pa := [4]byte{mqttPacketPubAck, 0x2, byte(pi >> 8), byte(pi)}
	if _, err := testMQTTWrite(cs, pa[:]); err != nil {
		t.Fatalf("Error writing PUBACK: %v", err)
	}
}

func TestMQTTv5Unsubscribe(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "v5unsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)

	testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "foo", opts: 0}})
	codes := testMQTTUnsubV5(t, c, r, 2, []string{"foo"})
	if len(codes) != 1 || codes[0] != mqttReasonSuccess {
		t.Fatalf("Expected one success reason code, got %v", codes)
	}
}

func TestMQTTv5DisconnectWithWill(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	subscribeToWill := func(t *testing.T, id string) (net.Conn, *mqttReader) {
		t.Helper()
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: id, cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "will/topic", opts: 0}})
		return c, r
	}

	will := &mqttWill{topic: []byte("will/topic"), message: []byte("bye"), qos: 0}

	t.Run("disconnect with will publishes it", func(t *testing.T) {
		cs, rs := subscribeToWill(t, "willsub1")
		defer cs.Close()

		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "willer1", cleanStart: true, will: will}, o.MQTT.Host, o.MQTT.Port)
		defer cw.Close()
		testMQTTReadConnAckV5(t, rw)

		// v5 DISCONNECT with reason 0x04 instructs the server to publish the will.
		dp := [3]byte{mqttPacketDisconnect, 1, mqttReasonDisconnectWithWill}
		if _, err := testMQTTWrite(cw, dp[:]); err != nil {
			t.Fatalf("Error writing DISCONNECT: %v", err)
		}

		testMQTTReadPublishV5(t, rs, "will/topic", []byte("bye"))
	})

	t.Run("normal disconnect discards will", func(t *testing.T) {
		cs, rs := subscribeToWill(t, "willsub2")
		defer cs.Close()

		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "willer2", cleanStart: true, will: will}, o.MQTT.Host, o.MQTT.Port)
		defer cw.Close()
		testMQTTReadConnAckV5(t, rw)

		// Normal v5 DISCONNECT (reason 0x00) discards the will.
		dp := [3]byte{mqttPacketDisconnect, 1, mqttReasonSuccess}
		if _, err := testMQTTWrite(cw, dp[:]); err != nil {
			t.Fatalf("Error writing DISCONNECT: %v", err)
		}

		testMQTTExpectNothing(t, rs)
	})
}

// mqttV5WillDelayProps returns a Will properties body (no length prefix, as
// expected by mqttV5ConnInfo.willProps) carrying only the Will Delay Interval.
func mqttV5WillDelayProps(delaySecs uint32) []byte {
	body := newMQTTWriter(0)
	body.WriteByte(mqttPropWillDelay)
	body.WriteUint32(delaySecs)
	return body.Bytes()
}

// mqttV5ConnPropsSessionExpiry returns a CONNECT properties body carrying only
// the Session Expiry Interval. A non-zero interval makes the session (and thus a
// delayed Will) survive the connection.
func mqttV5ConnPropsSessionExpiry(secs uint32) []byte {
	body := newMQTTWriter(0)
	body.WriteByte(mqttPropSessionExpiry)
	body.WriteUint32(secs)
	return body.Bytes()
}

// testMQTTNumPendingWills returns the number of delayed Wills currently pending
// on the account session manager, reached via a live client sharing the account.
func testMQTTNumPendingWills(t testing.TB, s *Server, liveClientID string) int {
	t.Helper()
	c := testMQTTGetClient(t, s, liveClientID)
	asm := c.mqtt.asm
	asm.mu.Lock()
	defer asm.mu.Unlock()
	return len(asm.pendingWills)
}

// The MQTT 5.0 Will Delay Interval defers publication of a client's Will until
// the delay elapses or the session ends. A reconnect to the same session before
// the delay cancels it; a clean session or a zero delay publishes immediately.
// Spec5 [3.1.3.2.2], [MQTT-3.1.2-8].
func TestMQTTv5WillDelay(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	subscribe := func(t *testing.T, id string, qos byte) (net.Conn, *mqttReader) {
		t.Helper()
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: id, cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "will/topic", opts: qos}})
		return c, r
	}

	t.Run("delay fires and publishes qos0", func(t *testing.T) {
		cs, rs := subscribe(t, "wdsub1", 0)
		defer cs.Close()

		will := &mqttWill{topic: []byte("will/topic"), message: []byte("bye"), qos: 0}
		// Clean start with a non-zero Session Expiry Interval: the session (and
		// the delayed Will) survives the disconnect even though the session object
		// is removed. Mirrors the conformance client.
		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wder1", cleanStart: true, will: will,
			willProps: mqttV5WillDelayProps(1), props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, rw)

		// Abruptly drop the connection: the will is deferred, not published now.
		cw.Close()
		checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
			if n := testMQTTNumPendingWills(t, s, "wdsub1"); n != 1 {
				return fmt.Errorf("expected 1 pending will, got %d", n)
			}
			return nil
		})
		testMQTTExpectNothing(t, rs)

		// After the delay elapses, the will is delivered.
		testMQTTReadPublishV5(t, rs, "will/topic", []byte("bye"))
	})

	t.Run("delay fires and publishes qos1", func(t *testing.T) {
		cs, rs := subscribe(t, "wdsub1b", 1)
		defer cs.Close()

		will := &mqttWill{topic: []byte("will/topic"), message: []byte("bye1"), qos: 1}
		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wder1b", will: will,
			willProps: mqttV5WillDelayProps(1), props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, rw)

		cw.Close()
		testMQTTExpectNothing(t, rs)
		// Exercises the QoS1 store path through the account JSA.
		testMQTTReadPublishV5(t, rs, "will/topic", []byte("bye1"))
	})

	t.Run("reconnect before delay cancels", func(t *testing.T) {
		cs, rs := subscribe(t, "wdsub2", 0)
		defer cs.Close()

		will := &mqttWill{topic: []byte("will/topic"), message: []byte("bye"), qos: 0}
		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wder2", cleanStart: true, will: will,
			willProps: mqttV5WillDelayProps(2), props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, rw)

		cw.Close()
		checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
			if n := testMQTTNumPendingWills(t, s, "wdsub2"); n != 1 {
				return fmt.Errorf("expected 1 pending will, got %d", n)
			}
			return nil
		})

		// Reconnect with the same client ID before the delay elapses: the will
		// MUST be cancelled, even though the clean-start session was removed on
		// disconnect. Spec5 [MQTT-3.1.2-8].
		cw2, rw2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wder2", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer cw2.Close()
		testMQTTReadConnAckV5(t, rw2)
		checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
			if n := testMQTTNumPendingWills(t, s, "wdsub2"); n != 0 {
				return fmt.Errorf("expected pending will cancelled, got %d", n)
			}
			return nil
		})
		// Even past the original delay, nothing is delivered.
		testMQTTExpectNothing(t, rs)
	})

	t.Run("zero delay publishes immediately", func(t *testing.T) {
		cs, rs := subscribe(t, "wdsub3", 0)
		defer cs.Close()

		will := &mqttWill{topic: []byte("will/topic"), message: []byte("bye"), qos: 0}
		// No willProps => Will Delay Interval 0 => immediate.
		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wder3", will: will}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, rw)

		cw.Close()
		testMQTTReadPublishV5(t, rs, "will/topic", []byte("bye"))
		if n := testMQTTNumPendingWills(t, s, "wdsub3"); n != 0 {
			t.Fatalf("expected no pending will for zero delay, got %d", n)
		}
	})

	t.Run("zero session expiry publishes immediately", func(t *testing.T) {
		cs, rs := subscribe(t, "wdsub4", 0)
		defer cs.Close()

		will := &mqttWill{topic: []byte("will/topic"), message: []byte("bye"), qos: 0}
		// A session with a zero (absent) Session Expiry Interval ends at
		// connection close, so the will is published immediately regardless of the
		// Will Delay Interval.
		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wder4", will: will,
			willProps: mqttV5WillDelayProps(2)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, rw)

		cw.Close()
		testMQTTReadPublishV5(t, rs, "will/topic", []byte("bye"))
		if n := testMQTTNumPendingWills(t, s, "wdsub4"); n != 0 {
			t.Fatalf("expected no pending will for zero session expiry, got %d", n)
		}
	})

	t.Run("disconnect-with-will honors delay", func(t *testing.T) {
		cs, rs := subscribe(t, "wdsub5", 0)
		defer cs.Close()

		will := &mqttWill{topic: []byte("will/topic"), message: []byte("bye"), qos: 0}
		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wder5", will: will,
			willProps: mqttV5WillDelayProps(1), props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, rw)

		// v5 DISCONNECT reason 0x04 keeps the will; the delay still applies.
		dp := [3]byte{mqttPacketDisconnect, 1, mqttReasonDisconnectWithWill}
		if _, err := testMQTTWrite(cw, dp[:]); err != nil {
			t.Fatalf("Error writing DISCONNECT: %v", err)
		}
		cw.Close()
		checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
			if n := testMQTTNumPendingWills(t, s, "wdsub5"); n != 1 {
				return fmt.Errorf("expected 1 pending will, got %d", n)
			}
			return nil
		})
		testMQTTExpectNothing(t, rs)
		testMQTTReadPublishV5(t, rs, "will/topic", []byte("bye"))
	})
}

// A delayed Will must still be subject to the publisher's publish permissions
// when the timer fires, exactly as an immediate Will is: a Will on a denied
// topic is dropped (not delivered, not retained), while one on an allowed topic
// is delivered. Guards against the deferred publish running with no permissions.
func TestMQTTv5WillDelayPermViolation(t *testing.T) {
	template := `
		port: -1
		jetstream {
			store_dir = %q
		}
		server_name: mqtt
		authorization {
			mqtt_perms = {
				publish = ["will.allowed"]
				subscribe = ["will.allowed", "will.denied"]
			}
			users = [
				{user: mqtt, password: pass, permissions: $mqtt_perms}
				{user: admin, password: pass}
			]
		}
		mqtt {
			port: -1
			max_protocol_version: 5
		}
	`
	tdir := t.TempDir()
	conf := createConfFile(t, fmt.Appendf(nil, template, tdir))
	s, o := RunServerWithConfig(conf)
	defer testMQTTShutdownServer(s)

	// Subscriber allowed to receive both will topics.
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wpsub", cleanStart: true, user: "mqtt", pass: "pass"},
		o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "will/allowed", opts: 0}, {topic: "will/denied", opts: 0}})

	// A delayed Will on a DENIED topic must be dropped when the timer fires.
	willDenied := &mqttWill{topic: []byte("will/denied"), message: []byte("nope"), qos: 0}
	cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wpdenied", user: "mqtt", pass: "pass",
		will: willDenied, willProps: mqttV5WillDelayProps(1), props: mqttV5ConnPropsSessionExpiry(30)},
		o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, rw)
	cw.Close()
	// Scheduled...
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		if n := testMQTTNumPendingWills(t, s, "wpsub"); n != 1 {
			return fmt.Errorf("expected 1 pending will, got %d", n)
		}
		return nil
	})
	// A denied Will must never be persisted with the session record: a restart
	// cannot re-check permissions, so a restored Will would bypass them. The
	// (would-be) record write races this check, so absence must hold for a
	// settle period, not just at one instant.
	nc, js := jsClientConnect(t, s, nats.UserInfo("admin", "pass"))
	sawRecord := false
	for deadline := time.Now().Add(750 * time.Millisecond); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		m, err := js.GetLastMsg(mqttSessStreamName, mqttSessStreamSubjectPrefix+getHash("wpdenied"))
		if err != nil {
			continue
		}
		sawRecord = true
		if bytes.Contains(m.Data, []byte(`"will"`)) {
			t.Fatal("denied will was persisted with the session record")
		}
	}
	if !sawRecord {
		t.Fatal("could not read the session record to verify the will was not persisted")
	}
	nc.Close()
	// ...then fired (removed from pending) and suppressed by publish permissions.
	checkFor(t, 3*time.Second, 20*time.Millisecond, func() error {
		if n := testMQTTNumPendingWills(t, s, "wpsub"); n != 0 {
			return fmt.Errorf("expected pending will to have fired, got %d", n)
		}
		return nil
	})
	testMQTTExpectNothing(t, rs)

	// A delayed Will on an ALLOWED topic is delivered normally.
	willOK := &mqttWill{topic: []byte("will/allowed"), message: []byte("ok"), qos: 0}
	cw2, rw2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wpok", user: "mqtt", pass: "pass",
		will: willOK, willProps: mqttV5WillDelayProps(1), props: mqttV5ConnPropsSessionExpiry(30)},
		o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, rw2)
	cw2.Close()
	testMQTTReadPublishV5(t, rs, "will/allowed", []byte("ok"))
}

// testMQTTGetClusterTemplateV5 is the standard MQTT cluster config template with
// MQTT 5.0 enabled.
func testMQTTGetClusterTemplateV5(t testing.TB) string {
	t.Helper()
	tmpl := strings.Replace(testMQTTGetClusterTemplaceNoLeaf(),
		"mqtt {\n\t\tlisten: 127.0.0.1:-1\n\t}",
		"mqtt {\n\t\tlisten: 127.0.0.1:-1\n\t\tmax_protocol_version: 5\n\t}", 1)
	if !strings.Contains(tmpl, "max_protocol_version: 5") {
		t.Fatal("failed to enable MQTT v5 in the cluster template")
	}
	return tmpl
}

// testMQTTConnectRetryV5 is testMQTTConnectRetry for a v5 CONNECT: it dials and
// sends the CONNECT, retrying on transient errors (useful while a cluster's JS
// assets are being set up). The returned reader is positioned to read the CONNACK.
func testMQTTConnectRetryV5(t testing.TB, ci *mqttV5ConnInfo, host string, port, retryCount int) (net.Conn, *mqttReader) {
	t.Helper()
	retry := func(c net.Conn) bool {
		if c != nil {
			c.Close()
		}
		if retryCount == 0 {
			return false
		}
		time.Sleep(time.Second)
		retryCount--
		return true
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	var c net.Conn
	var err error
	var buf []byte
RETRY:
	if c, err = net.Dial("tcp", addr); err != nil {
		if retry(c) {
			goto RETRY
		}
		t.Fatalf("Error dialing: %v", err)
	}
	if _, err = testMQTTWrite(c, mqttV5CreateConnect(ci)); err != nil {
		if retry(c) {
			goto RETRY
		}
		t.Fatalf("Error writing connect: %v", err)
	}
	if buf, err = testMQTTRead(c); err != nil {
		if retry(c) {
			goto RETRY
		}
		t.Fatalf("Error reading connack: %v", err)
	}
	mr := &mqttReader{reader: c}
	mr.reset(buf)
	return c, mr
}

// In a cluster, a delayed Will scheduled on the server the client left must be
// cancelled when the client reconnects to a DIFFERENT server before the delay
// elapses: the session-persist propagation cancels the pending Will remotely.
// Spec5 [MQTT-3.1.2-8].
func TestMQTTv5WillDelayCluster(t *testing.T) {
	cl := createJetStreamClusterWithTemplate(t, testMQTTGetClusterTemplateV5(t), "MQTT", 2)
	defer cl.shutdown()

	srvA, optsA := cl.servers[0], cl.opts[0]
	optsB := cl.opts[1]

	t.Run("fires and is delivered across servers", func(t *testing.T) {
		// Subscriber on server B.
		cs, rs := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "wdcsub1", cleanStart: true},
			optsB.MQTT.Host, optsB.MQTT.Port, 5)
		defer cs.Close()
		testMQTTReadConnAckV5(t, rs)
		testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "will/topic", opts: 1}})

		// Will client on server A, QoS1 (JetStream-backed, robust across the
		// cluster), short delay.
		will := &mqttWill{topic: []byte("will/topic"), message: []byte("bye"), qos: 1}
		cw, rw := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "wdcwill1", will: will,
			willProps: mqttV5WillDelayProps(1), props: mqttV5ConnPropsSessionExpiry(30)},
			optsA.MQTT.Host, optsA.MQTT.Port, 5)
		testMQTTReadConnAckV5(t, rw)
		cw.Close()

		// After the delay, the will fires on A and is delivered to the subscriber on B.
		testMQTTReadPublishV5(t, rs, "will/topic", []byte("bye"))
	})

	t.Run("reconnect to another server cancels the will", func(t *testing.T) {
		// Prober/subscriber on server A so we can inspect server A's pending wills.
		cprobe, rprobe := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "wdcprobe", cleanStart: true},
			optsA.MQTT.Host, optsA.MQTT.Port, 5)
		defer cprobe.Close()
		testMQTTReadConnAckV5(t, rprobe)
		testMQTTSubV5(t, cprobe, rprobe, 1, []mqttV5SubFilter{{topic: "will/topic2", opts: 0}})

		// Will client on server A with a long delay so the timer cannot fire during
		// the test: any removal from server A's pending wills must be a cancellation.
		will := &mqttWill{topic: []byte("will/topic2"), message: []byte("bye"), qos: 0}
		cw, rw := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "wdcwill2", will: will,
			willProps: mqttV5WillDelayProps(30), props: mqttV5ConnPropsSessionExpiry(60)},
			optsA.MQTT.Host, optsA.MQTT.Port, 5)
		testMQTTReadConnAckV5(t, rw)
		cw.Close()

		// Scheduled on server A.
		checkFor(t, 3*time.Second, 20*time.Millisecond, func() error {
			if n := testMQTTNumPendingWills(t, srvA, "wdcprobe"); n != 1 {
				return fmt.Errorf("expected 1 pending will on server A, got %d", n)
			}
			return nil
		})

		// Reconnect the same client ID on server B before the 30s delay: a new
		// connection to the session, so server A must cancel its pending will via
		// the session-persist callback.
		cw2, rw2 := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "wdcwill2", cleanStart: true},
			optsB.MQTT.Host, optsB.MQTT.Port, 5)
		defer cw2.Close()
		testMQTTReadConnAckV5(t, rw2)

		// Server A cancels its pending will well before the 30s delay could elapse,
		// so the removal is a cancellation (not a firing).
		checkFor(t, 5*time.Second, 20*time.Millisecond, func() error {
			if n := testMQTTNumPendingWills(t, srvA, "wdcprobe"); n != 0 {
				return fmt.Errorf("expected server A pending will to be cancelled, got %d", n)
			}
			return nil
		})
		testMQTTExpectNothing(t, rprobe)
	})
}

func TestMQTTv5MaxProtocolVersionConfigParse(t *testing.T) {
	for _, test := range []struct {
		name    string
		val     string
		want    byte
		wantErr bool
	}{
		{"cap to 3.1.1", "4", 4, false},
		{"enable v5", "5", 5, false},
		{"default (v5 disabled)", "0", 0, false},
		{"invalid", "3", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := createConfFile(t, []byte(fmt.Sprintf(`
				listen: "127.0.0.1:-1"
				jetstream: enabled
				mqtt {
					listen: "127.0.0.1:-1"
					max_protocol_version: %s
				}
			`, test.val)))
			o, err := ProcessConfigFile(conf)
			if test.wantErr {
				if err == nil {
					t.Fatal("Expected a config error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected config error: %v", err)
			}
			if o.MQTT.MaxProtocolVersion != test.want {
				t.Fatalf("Expected MaxProtocolVersion=%d, got %d", test.want, o.MQTT.MaxProtocolVersion)
			}
		})
	}
}

// A v5 subscriber must correctly receive a message published by a 3.1.1 client
// (exercises the outbound v5 PUBLISH framing with the empty properties field).
func TestMQTTv5InteropWith311Publisher(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "v5sub2", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "interop", opts: 0}})

	// 3.1.1 publisher.
	cp, rp := testMQTTConnect(t, &mqttConnInfo{clientID: "v311pub", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTCheckConnAck(t, rp, mqttConnAckRCConnectionAccepted, false)
	testMQTTPublish(t, cp, rp, 0, false, false, "interop", 0, []byte("from-311"))

	testMQTTReadPublishV5(t, rs, "interop", []byte("from-311"))
}

// A SUBSCRIBE must be rejected (not silently ACKed) for an invalid v5
// subscription options byte: a Retain Handling value of 3 is reserved (Protocol
// Error), and the reserved bits 6-7 are a Malformed Packet. The honored options
// are covered by TestMQTTv5RetainHandling, TestMQTTv5NoLocal and
// TestMQTTv5RetainAsPublished.
func TestMQTTv5RejectsUnsupportedSubOptions(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	for _, test := range []struct {
		name      string
		opts      byte
		expReason byte
	}{
		{"retain handling 3 reserved", 0x30, mqttReasonProtocolError},
		{"retain handling 3 with other option bits", 0x3C, mqttReasonProtocolError},
		{"reserved bit 6", 0x40, mqttReasonMalformedPacket},
		{"reserved bit 7", 0x80, mqttReasonMalformedPacket},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "subopt", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer c.Close()
			testMQTTReadConnAckV5(t, r)

			// Craft a v5 SUBSCRIBE with QoS 1 plus the rejected option bit(s).
			vh := newMQTTWriter(0)
			vh.WriteUint16(1)
			vh.WriteVarInt(0) // empty properties
			vh.WriteBytes([]byte("foo"))
			vh.WriteByte(0x01 | test.opts)
			w := newMQTTWriter(0)
			w.WriteByte(mqttPacketSub | mqttSubscribeFlags)
			w.WriteVarInt(vh.Len())
			w.Write(vh.Bytes())
			if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
				t.Fatalf("Error writing SUBSCRIBE: %v", err)
			}

			// The server must NOT send a SUBACK; it sends a v5 DISCONNECT with the
			// classified reason code before closing.
			b, _ := testMQTTReadPacket(t, r)
			if pt := b & mqttPacketMask; pt != mqttPacketDisconnect {
				t.Fatalf("Expected DISCONNECT (%x), got %x", mqttPacketDisconnect, pt)
			}
			reason, err := r.readByte("disconnect reason")
			if err != nil {
				t.Fatalf("Error reading disconnect reason: %v", err)
			}
			if reason != test.expReason {
				t.Fatalf("Expected disconnect reason 0x%x, got 0x%x", test.expReason, reason)
			}
		})
	}
}

// Shared Subscriptions are advertised as unavailable in CONNACK, so a
// "$share/..." filter must be rejected with SUBACK reason code 0x9E, not
// subscribed to as a literal topic (which would silently deliver nothing).
// Other filters in the same SUBSCRIBE must still be granted. Spec5 [3.9.3].
func TestMQTTv5SharedSubscriptionRejected(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sharesub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)

	codes := testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{
		{topic: "foo", opts: 1},
		{topic: "$share/grp/foo", opts: 1},
		{topic: "bar", opts: 0},
	})
	if codes[0] != 1 || codes[1] != mqttReasonSharedSubNotSupported || codes[2] != 0 {
		t.Fatalf("Expected SUBACK codes [1, 0x9e, 0], got %x", codes)
	}

	// The rejected filter must not exist as a literal subscription: a message
	// published to the literal topic must not be delivered.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sharepub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPublishV5(t, cp, 0, 0, "$share/grp/foo", []byte("literal"))
	testMQTTExpectNothing(t, r)

	// The granted filter still works.
	testMQTTPublishV5(t, cp, 0, 0, "foo", []byte("msg"))
	testMQTTReadPublishV5(t, r, "foo", []byte("msg"))
}

// The v5 Retain Handling subscription option controls whether retained messages
// are replayed at subscribe time: 0 always, 1 only when the subscription is new,
// 2 never. Spec5 [3.8.3.1].
func TestMQTTv5RetainHandling(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// Publish a retained message the subscribers below will (or won't) receive.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rhpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, true, 1, "rh/topic", []byte("retained"), nil)

	// opts byte: QoS in bits 0-1, Retain Handling in bits 4-5.
	rhOpts := func(qos, rh byte) byte { return qos | (rh << 4) }

	t.Run("RH=0 sends retained", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rh0", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "rh/topic", opts: rhOpts(1, 0)}})
		testMQTTReadPubV5Props(t, c, r, "rh/topic", []byte("retained"))
	})

	t.Run("RH=2 never sends retained", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rh2", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "rh/topic", opts: rhOpts(1, 2)}})
		testMQTTExpectNothing(t, r)
		// A live publish still reaches the subscription, proving it is active and
		// only the retained replay was suppressed.
		testMQTTPubV5Props(t, cp, rp, 1, false, 2, "rh/topic", []byte("live"), nil)
		testMQTTReadPubV5Props(t, c, r, "rh/topic", []byte("live"))
	})

	t.Run("RH=1 sends only for a new subscription", func(t *testing.T) {
		// The retained message must already exist before the first subscribe so
		// that a "new subscription" replay is actually exercised.
		testMQTTPubV5Props(t, cp, rp, 1, true, 3, "rh1/topic", []byte("retained1"), nil)

		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rh1", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		// First subscribe: the subscription is new, so retained is replayed.
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "rh1/topic", opts: rhOpts(1, 1)}})
		testMQTTReadPubV5Props(t, c, r, "rh1/topic", []byte("retained1"))
		// Re-subscribe to the same filter: the subscription already exists, so no
		// retained replay. A live publish confirms the sub is still active.
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "rh1/topic", opts: rhOpts(1, 1)}})
		testMQTTExpectNothing(t, r)
		testMQTTPubV5Props(t, cp, rp, 1, false, 4, "rh1/topic", []byte("live1"), nil)
		testMQTTReadPubV5Props(t, c, r, "rh1/topic", []byte("live1"))
	})

	// Retain Handling is per-subscription: an RH=2 filter in the same SUBSCRIBE
	// as an overlapping RH=0 wildcard must not itself replay retained messages,
	// even though the shared preload loads the subject for the wildcard.
	t.Run("RH=2 not leaked by overlapping RH=0 filter", func(t *testing.T) {
		testMQTTPubV5Props(t, cp, rp, 1, true, 5, "ov/topic", []byte("retained-ov"), nil)

		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rhov", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		// ov/+ (RH=0) matches the retained ov/topic; ov/topic (RH=2) must not add
		// a second copy. Both are QoS1 so ordering within the SUBACK is stable.
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{
			{topic: "ov/+", opts: rhOpts(1, 0)},
			{topic: "ov/topic", opts: rhOpts(1, 2)},
		})
		// Exactly one retained delivery (via ov/+), then nothing more.
		testMQTTReadPubV5Props(t, c, r, "ov/topic", []byte("retained-ov"))
		testMQTTExpectNothing(t, r)
	})
}

// The v5 Retain As Published subscription option (bit 3) controls the RETAIN
// flag on a live-forwarded message: kept as published when set, cleared when
// not. A retained replay to a new subscription always has RETAIN=1 regardless.
// Spec5 [3.8.3.1].
func TestMQTTv5RetainAsPublished(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	const rapBit = byte(0x08)

	// runRAP: with both subscriptions established, a retained publish is forwarded
	// live keeping RETAIN only for the Retain As Published subscriber.
	runRAP := func(t *testing.T, qos byte, prefix string) {
		topic := prefix + "/t"

		a, ra := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: prefix + "-rap", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer a.Close()
		testMQTTReadConnAckV5(t, ra)
		testMQTTSubV5(t, a, ra, 1, []mqttV5SubFilter{{topic: topic, opts: qos | rapBit}})

		b, rb := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: prefix + "-plain", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer b.Close()
		testMQTTReadConnAckV5(t, rb)
		testMQTTSubV5(t, b, rb, 1, []mqttV5SubFilter{{topic: topic, opts: qos}})

		p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: prefix + "-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer p.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, p, rp, qos, true, 1, topic, []byte("m"), nil)

		// RAP subscriber keeps RETAIN=1; the default subscriber gets RETAIN=0.
		testMQTTReadPubCheckRetainV5(t, a, ra, topic, []byte("m"), true)
		testMQTTReadPubCheckRetainV5(t, b, rb, topic, []byte("m"), false)
	}

	t.Run("QoS0", func(t *testing.T) { runRAP(t, 0, "rap0") })
	t.Run("QoS1", func(t *testing.T) { runRAP(t, 1, "rap1") })

	// A retained message replayed to a NEW subscription always has RETAIN=1, even
	// when that subscription did not request Retain As Published.
	t.Run("retained replay always sets RETAIN", func(t *testing.T) {
		p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rapr-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer p.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, p, rp, 1, true, 1, "rapr/t", []byte("kept"), nil)

		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rapr-sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "rapr/t", opts: 1}}) // no RAP
		testMQTTReadPubCheckRetainV5(t, c, r, "rapr/t", []byte("kept"), true)
	})

	// A QoS2 retained publish keeps RETAIN through the hold/PUBREL release: the
	// original RETAIN is restored from the stored marker on release. Subscribe at
	// QoS1 so the capped delivery is a simple PUBACK.
	t.Run("QoS2 publish keeps RETAIN via PUBREL", func(t *testing.T) {
		a, ra := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rap2-rap", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer a.Close()
		testMQTTReadConnAckV5(t, ra)
		testMQTTSubV5(t, a, ra, 1, []mqttV5SubFilter{{topic: "rap2/t", opts: 1 | rapBit}})

		p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rap2-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer p.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, p, rp, 2, true, 1, "rap2/t", []byte("q2"), nil)
		testMQTTReadPubCheckRetainV5(t, a, ra, "rap2/t", []byte("q2"), true)
	})

	// The Nmqtt-Ret marker is honored only when its value is exactly "1"; an
	// explicit "0" (or junk) from a NATS publisher must not make a Retain As
	// Published subscriber see RETAIN=1.
	t.Run("Nmqtt-Ret not exactly 1 is not retained", func(t *testing.T) {
		a, ra := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rap-neg", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer a.Close()
		testMQTTReadConnAckV5(t, ra)
		testMQTTSubV5(t, a, ra, 1, []mqttV5SubFilter{{topic: "rapn/t", opts: rapBit}}) // QoS0 + RAP

		nc := natsConnect(t, s.ClientURL())
		defer nc.Close()
		hdr := nats.Header{}
		hdr.Set(mqttNatsHeader, "0")
		hdr.Set(mqttNatsHeaderRetain, "0") // not "1": must not be treated as retained
		if err := nc.PublishMsg(&nats.Msg{Subject: "rapn.t", Header: hdr, Data: []byte("z")}); err != nil {
			t.Fatalf("nats publish: %v", err)
		}
		nc.Flush()
		testMQTTReadPubCheckRetainV5(t, a, ra, "rapn/t", []byte("z"), false)
	})

	// Retain As Published is part of the session state and must survive a
	// reconnect of a persistent session.
	t.Run("survives reconnect", func(t *testing.T) {
		ci := &mqttV5ConnInfo{clientID: "rap-persist", props: mqttV5ConnPropsSessionExpiry(30)}
		c, r := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "rapp/t", opts: 1 | rapBit}})
		if _, err := testMQTTWrite(c, []byte{mqttPacketDisconnect, 0}); err != nil {
			t.Fatalf("Error writing DISCONNECT: %v", err)
		}
		c.Close()

		c2, r2 := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); !sp {
			t.Fatal("Expected session present on reconnect")
		}
		p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rapp-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer p.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, p, rp, 1, true, 1, "rapp/t", []byte("after"), nil)
		// The restored subscription still keeps RETAIN as published.
		testMQTTReadPubCheckRetainV5(t, c2, r2, "rapp/t", []byte("after"), true)
	})
}

// The v5 No Local subscription option (bit 2) must stop a message from being
// delivered back to the connection that published it, while a message from a
// different connection still arrives. Spec5 [3.8.3.1].
func TestMQTTv5NoLocal(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// opts byte: QoS in bits 0-1, No Local in bit 2.
	const noLocalBit = byte(0x04)

	// runNoLocal exercises the option at the given QoS: the No Local subscriber
	// must not get its own publish, but must get another connection's.
	runNoLocal := func(t *testing.T, qos byte, prefix string) {
		topic := prefix + "/topic"

		a, ra := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: prefix + "-a", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer a.Close()
		testMQTTReadConnAckV5(t, ra)
		testMQTTSubV5(t, a, ra, 1, []mqttV5SubFilter{{topic: topic, opts: qos | noLocalBit}})

		b, rb := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: prefix + "-b", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer b.Close()
		testMQTTReadConnAckV5(t, rb)
		testMQTTSubV5(t, b, rb, 1, []mqttV5SubFilter{{topic: topic, opts: qos}})

		// A publishes: its own No Local subscription must not receive it; B (which
		// did not set No Local) must. A gets only the PUBACK (its self-delivery is
		// suppressed), so there is no self-echo race here.
		testMQTTPubV5Props(t, a, ra, qos, false, 1, topic, []byte("from-a"), nil)
		testMQTTReadPubV5Props(t, b, rb, topic, []byte("from-a"))
		testMQTTExpectNothing(t, ra)

		// A different, unsubscribed connection publishes: A must receive it, since
		// No Local only blocks A's own publishes. Using a non-subscribed publisher
		// avoids a self-echo racing the PUBACK.
		p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: prefix + "-p", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer p.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, p, rp, qos, false, 1, topic, []byte("from-p"), nil)
		testMQTTReadPubV5Props(t, a, ra, topic, []byte("from-p"))
	}

	t.Run("QoS0", func(t *testing.T) { runNoLocal(t, 0, "nl0") })
	t.Run("QoS1", func(t *testing.T) { runNoLocal(t, 1, "nl1") })

	// No Local is part of the session state, so it must survive a reconnect of a
	// persistent session (verifies the option is packed into the stored subs).
	t.Run("survives reconnect", func(t *testing.T) {
		ci := &mqttV5ConnInfo{clientID: "nl-persist", props: mqttV5ConnPropsSessionExpiry(30)}
		c, r := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "nlp/topic", opts: 1 | noLocalBit}})
		// Clean v5 DISCONNECT (reason 0), which keeps the session alive.
		if _, err := testMQTTWrite(c, []byte{mqttPacketDisconnect, 0}); err != nil {
			t.Fatalf("Error writing DISCONNECT: %v", err)
		}
		c.Close()

		// Reconnect the same client ID with a persistent session; the No Local
		// subscription is restored. Its own publish must still be suppressed.
		c2, r2 := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); !sp {
			t.Fatal("Expected session present on reconnect")
		}
		testMQTTPubV5Props(t, c2, r2, 1, false, 1, "nlp/topic", []byte("own"), nil)
		testMQTTExpectNothing(t, r2)

		// A different connection publishing to the same topic still reaches it.
		other, ro := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "nlp-other", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer other.Close()
		testMQTTReadConnAckV5(t, ro)
		testMQTTPubV5Props(t, other, ro, 1, false, 1, "nlp/topic", []byte("external"), nil)
		testMQTTReadPubV5Props(t, c2, r2, "nlp/topic", []byte("external"))
	})

	// Re-subscribing an existing QoS1 filter must refresh No Local on the
	// JetStream delivery subscription used by the QoS 1/2 callback.
	t.Run("QoS1 re-subscribe toggles No Local", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "nlt", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)

		// Without No Local the client receives its own publish (PUBACK and the
		// self-echo can arrive in either order).
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "nlt/topic", opts: 1}})
		testMQTTPubV5SelfEcho(t, c, r, 1, "nlt/topic", []byte("m1"))

		// Re-subscribe with No Local: its own publish is now suppressed.
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "nlt/topic", opts: 1 | noLocalBit}})
		testMQTTPubV5Props(t, c, r, 1, false, 2, "nlt/topic", []byte("m2"), nil)
		testMQTTExpectNothing(t, r)

		// Toggle No Local back off: its own publish is delivered again.
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "nlt/topic", opts: 1}})
		testMQTTPubV5SelfEcho(t, c, r, 1, "nlt/topic", []byte("m3"))
	})

	// No Local must also suppress replaying a retained message the same session
	// published, while a different session's No Local subscription still gets it.
	t.Run("retained is suppressed for the publishing session", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "nlr", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTPubV5Props(t, c, r, 1, true, 1, "nlr/topic", []byte("retained"), nil)

		// Same session subscribes with No Local: its own retained is not replayed.
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "nlr/topic", opts: 1 | noLocalBit}})
		testMQTTExpectNothing(t, r)

		// A different session with No Local still receives the retained message.
		d, rd := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "nlr-other", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer d.Close()
		testMQTTReadConnAckV5(t, rd)
		testMQTTSubV5(t, d, rd, 1, []mqttV5SubFilter{{topic: "nlr/topic", opts: 1 | noLocalBit}})
		testMQTTReadPubV5Props(t, d, rd, "nlr/topic", []byte("retained"))
	})

	// No Local on a Shared Subscription is a Protocol Error. Spec5 [MQTT-3.8.3-4].
	t.Run("no local on shared subscription rejected", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "nlsh", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)

		vh := newMQTTWriter(0)
		vh.WriteUint16(1)
		vh.WriteVarInt(0)
		vh.WriteBytes([]byte("$share/g/f"))
		vh.WriteByte(0x01 | noLocalBit)
		w := newMQTTWriter(0)
		w.WriteByte(mqttPacketSub | mqttSubscribeFlags)
		w.WriteVarInt(vh.Len())
		w.Write(vh.Bytes())
		if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
			t.Fatalf("Error writing SUBSCRIBE: %v", err)
		}
		b, _ := testMQTTReadPacket(t, r)
		if pt := b & mqttPacketMask; pt != mqttPacketDisconnect {
			t.Fatalf("Expected DISCONNECT (%x), got %x", mqttPacketDisconnect, pt)
		}
		reason, err := r.readByte("disconnect reason")
		if err != nil {
			t.Fatalf("Error reading disconnect reason: %v", err)
		}
		if reason != mqttReasonProtocolError {
			t.Fatalf("Expected reason 0x%x (protocol error), got 0x%x", mqttReasonProtocolError, reason)
		}
	})

	// A Will is server-originated, so it carries no No Local origin regardless of
	// which Will path fires or whether it is stored as retained. A subscriber
	// with the same client ID as the Will owner, using No Local, must still
	// receive the retained Will. Spec5 [3.8.3.1].
	t.Run("retained will is not subject to No Local", func(t *testing.T) {
		retWill := &mqttWill{topic: []byte("wnl/topic"), message: []byte("gone"), qos: 0, retain: true}
		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wnl", cleanStart: true, will: retWill}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, rw)
		// Reason 0x04 tells the server to publish the Will immediately.
		if _, err := testMQTTWrite(cw, []byte{mqttPacketDisconnect, 1, mqttReasonDisconnectWithWill}); err != nil {
			t.Fatalf("Error writing DISCONNECT: %v", err)
		}
		cw.Close()

		// Reconnect with the same client ID and a No Local subscription. The Will
		// is server-originated (no origin stamped, on either the live header or the
		// retained copy), so it is delivered rather than suppressed.
		cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wnl", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer cs.Close()
		testMQTTReadConnAckV5(t, rs)
		// The retained Will store is asynchronous with no ack to wait on, so poll:
		// re-subscribing replays retained at RH=0. A PUBLISH arriving proves the
		// Will was not suppressed by this same-ID No Local subscription.
		var delivered bool
		for i := 0; i < 20 && !delivered; i++ {
			testMQTTSubV5(t, cs, rs, uint16(i+1), []mqttV5SubFilter{{topic: "wnl/topic", opts: noLocalBit}})
			if b, _, ok := testMQTTReadPacketReady(rs, 150*time.Millisecond); ok && b&mqttPacketMask == mqttPacketPub {
				delivered = true
			}
		}
		if !delivered {
			t.Fatal("retained Will was not delivered to a same-ID No Local subscription")
		}
	})
}

// A No Local origin supplied by a plain NATS client must not be trusted: the
// origin marker is an HMAC under a per-server secret, so a client cannot forge
// one for a victim's session and silently drop that subscriber's messages. This
// covers both delivery paths that carry the marker.
func TestMQTTv5NoLocalOriginNotSpoofable(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// QoS0 direct path: a NATS client publishes to the subscriber's subject with
	// a forged Nmqtt-Origin. The QoS0 path never trusts the header (suppression
	// is only from a local MQTT publisher), so the message is delivered.
	t.Run("QoS0 direct", func(t *testing.T) {
		cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "spoofsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer cs.Close()
		testMQTTReadConnAckV5(t, rs)
		testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "spoof/x", opts: 0x04}}) // No Local

		nc := natsConnect(t, s.ClientURL())
		defer nc.Close()
		hdr := nats.Header{}
		hdr.Set(mqttNatsHeader, "0") // parse MQTT metadata on the delivery path
		hdr.Set(mqttNatsHeaderOrigin, getHash("spoofsub"))
		if err := nc.PublishMsg(&nats.Msg{Subject: "spoof.x", Header: hdr, Data: []byte("attack")}); err != nil {
			t.Fatalf("nats publish: %v", err)
		}
		nc.Flush()
		testMQTTReadPublishV5(t, rs, "spoof/x", []byte("attack"))
	})

	// QoS1/2 path: a NATS client with access to the MQTT stream subject injects a
	// QoS1-looking message carrying a forged Nmqtt-Origin. The stored marker is
	// HMAC-authenticated, so the forgery fails verification and the victim's No
	// Local QoS1 subscription still receives the message.
	t.Run("QoS1 stream injection", func(t *testing.T) {
		cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "spoofq", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer cs.Close()
		testMQTTReadConnAckV5(t, rs)
		testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "spoofq/x", opts: 0x01 | 0x04}}) // QoS1 + No Local

		nc := natsConnect(t, s.ClientURL())
		defer nc.Close()
		hdr := nats.Header{}
		hdr.Set(mqttNatsHeader, "1") // QoS1
		hdr.Set(mqttNatsHeaderOrigin, getHash("spoofq"))
		// Inject directly into the MQTT messages stream subject for spoofq.x.
		if err := nc.PublishMsg(&nats.Msg{Subject: mqttStreamSubjectPrefix + "spoofq.x", Header: hdr, Data: []byte("attack")}); err != nil {
			t.Fatalf("nats publish: %v", err)
		}
		nc.Flush()
		testMQTTReadPublishV5(t, rs, "spoofq/x", []byte("attack"))
	})
}

// The origin marker is deterministic and emitted in a readable header, so it can
// be observed and replayed. That is benign: the marker only authenticates "this
// subscriber's own session published this subject+payload", so replaying a
// victim's marker can at most re-assert the victim's own origin (which No Local
// suppresses anyway), and cannot suppress an independently-authored message,
// which carries a different origin's marker. Spec5 [3.8.3.1].
func TestMQTTv5NoLocalMarkerReplayIsBenign(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// A plain NATS client on the subject observes the marker the victim emits.
	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()
	obs, err := nc.SubscribeSync("rpx")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	nc.Flush()

	v, rv := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rpvic", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer v.Close()
	testMQTTReadConnAckV5(t, rv)
	testMQTTSubV5(t, v, rv, 1, []mqttV5SubFilter{{topic: "rpx", opts: 0x01 | 0x04}}) // QoS1 + No Local
	testMQTTPubV5Props(t, v, rv, 1, false, 1, "rpx", []byte("P"), nil)
	testMQTTExpectNothing(t, rv) // own message suppressed

	// Capture the emitted origin marker from the live NATS delivery.
	m, err := obs.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	marker := m.Header.Get(mqttNatsHeaderOrigin)
	if marker == _EMPTY_ {
		t.Fatal("expected an origin marker on the observed message")
	}

	// Replay the observed marker with the same payload into the messages stream.
	// It re-asserts the victim's own origin, so it is suppressed (harmless): the
	// attacker only gets its own injected duplicate dropped.
	hdr := nats.Header{}
	hdr.Set(mqttNatsHeader, "1")
	hdr.Set(mqttNatsHeaderOrigin, marker)
	if err := nc.PublishMsg(&nats.Msg{Subject: mqttStreamSubjectPrefix + "rpx", Header: hdr, Data: []byte("P")}); err != nil {
		t.Fatalf("nats publish: %v", err)
	}
	nc.Flush()
	testMQTTExpectNothing(t, rv)

	// A legitimate third MQTT publisher sending the SAME payload is delivered:
	// its message carries a different origin's marker, so the replay cannot deny
	// independently-authored traffic.
	w, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rpw", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer w.Close()
	testMQTTReadConnAckV5(t, rw)
	testMQTTPubV5Props(t, w, rw, 1, false, 1, "rpx", []byte("P"), nil)
	testMQTTReadPubV5Props(t, v, rv, "rpx", []byte("P"))
}

// No Local must still suppress a QoS1 self-published message when a subject
// mapping rewrites the published subject: the origin marker must bind the same
// (mapped) subject the message is stored and delivered under. Spec5 [3.8.3.1].
func TestMQTTv5NoLocalWithSubjectMapping(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// Mapping is on NATS subjects; use single-level topics so the MQTT topic and
	// NATS subject coincide (nlfoo -> nlbar).
	if err := s.GlobalAccount().AddMapping("nlfoo", "nlbar"); err != nil {
		t.Fatalf("AddMapping: %v", err)
	}

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "nlmap", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)
	// Subscribe to the mapped destination with No Local, publish to the source
	// (rewritten to the destination). The client must not receive its own message.
	testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "nlbar", opts: 0x01 | 0x04}})
	testMQTTPubV5Props(t, c, r, 1, false, 1, "nlfoo", []byte("mapped"), nil)
	testMQTTExpectNothing(t, r)

	// A different connection publishing to the source still reaches it.
	other, ro := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "nlmap-other", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer other.Close()
	testMQTTReadConnAckV5(t, ro)
	testMQTTPubV5Props(t, other, ro, 1, false, 1, "nlfoo", []byte("external"), nil)
	testMQTTReadPubV5Props(t, c, r, "nlbar", []byte("external"))
}

// Re-subscribing an existing QoS 1/2 filter at a different QoS must update the
// delivery cap used by the QoS 1/2 callback, which reads it off the (unchanged)
// JetStream delivery subscription. Spec5 [MQTT-3.8.4-3].
func TestMQTTv5ResubscribeRefreshesDeliveryQoS(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	sub, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rq-sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer sub.Close()
	testMQTTReadConnAckV5(t, rs)
	// Subscribe at QoS2, then re-subscribe the same filter down to QoS1.
	testMQTTSubV5(t, sub, rs, 1, []mqttV5SubFilter{{topic: "rq/topic", opts: 2}})
	testMQTTSubV5(t, sub, rs, 1, []mqttV5SubFilter{{topic: "rq/topic", opts: 1}})

	pub, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rq-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer pub.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, pub, rp, 2, false, 1, "rq/topic", []byte("m"), nil)

	// Delivery must be capped at the re-subscribed QoS1, not the original QoS2
	// (which would open a PUBREC handshake instead of a PUBACK).
	qos, pi := testMQTTReadPublishV5(t, rs, "rq/topic", []byte("m"))
	if qos != 1 {
		t.Fatalf("Expected delivery at QoS1 after re-subscribe, got QoS%d", qos)
	}
	testMQTTSendPIPacket(mqttPacketPubAck, t, sub, pi)
}

// MaxProtocolVersion must be range-checked for programmatic Options too, not
// only when parsed from a config file. Otherwise an out-of-range value (e.g. 3)
// would cause the runtime cap to reject even MQTT 3.1.1 connections.
func TestMQTTv5MaxProtocolVersionValidation(t *testing.T) {
	o := testMQTTDefaultOptions()
	o.MQTT.MaxProtocolVersion = 3
	if err := validateMQTTOptions(o); err == nil {
		t.Fatal("Expected a validation error for MaxProtocolVersion=3")
	}
	for _, v := range []byte{0, 4, 5} {
		o.MQTT.MaxProtocolVersion = v
		if err := validateMQTTOptions(o); err != nil {
			t.Fatalf("Unexpected validation error for MaxProtocolVersion=%d: %v", v, err)
		}
	}
}

// A v5 UNSUBACK must report 0x11 (No subscription existed) per filter that was
// not subscribed, not a blanket success. Spec5 [3.11.3].
func TestMQTTv5UnsubscribeNoSubscriptionExisted(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "nosub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)

	testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "foo", opts: 0}})
	codes := testMQTTUnsubV5(t, c, r, 2, []string{"foo", "never/subscribed"})
	if len(codes) != 2 || codes[0] != mqttReasonSuccess || codes[1] != mqttReasonNoSubscriptionExisted {
		t.Fatalf("Expected [0x00 0x11], got %v", codes)
	}
}

// A v5 PUBCOMP for a PUBREL whose packet identifier has no session state must
// carry reason 0x92 (Packet Identifier not found). Spec5 [MQTT-4.3.3-1].
func TestMQTTv5PubCompPacketIDNotFound(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "pubrel92", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)

	// PUBREL for a PI the server has never seen.
	if _, err := testMQTTWrite(c, []byte{mqttPacketPubRel | 0x2, 2, 0, 42}); err != nil {
		t.Fatalf("Error writing PUBREL: %v", err)
	}
	b, pl := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketPubComp {
		t.Fatalf("Expected PUBCOMP (%x), got %x", mqttPacketPubComp, pt)
	}
	if pi, err := r.readUint16("pubcomp pi"); err != nil || pi != 42 {
		t.Fatalf("Expected PUBCOMP pi=42, got %v (err=%v)", pi, err)
	}
	if pl < 3 {
		t.Fatalf("Expected a PUBCOMP reason code, got remaining length %d", pl)
	}
	reason, err := r.readByte("pubcomp reason")
	if err != nil {
		t.Fatalf("Error reading PUBCOMP reason: %v", err)
	}
	if reason != mqttReasonPacketIDNotFound {
		t.Fatalf("Expected reason 0x%x (packet ID not found), got 0x%x", mqttReasonPacketIDNotFound, reason)
	}
}

// An evicted v5 client must be told the session was taken over with a
// DISCONNECT 0x8E before the connection closes. Spec5 [3.1.4].
func TestMQTTv5SessionTakenOverDisconnect(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c1, r1 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "takeover", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c1.Close()
	testMQTTReadConnAckV5(t, r1)

	c2, r2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "takeover", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c2.Close()
	testMQTTReadConnAckV5(t, r2)

	b, _ := testMQTTReadPacket(t, r1)
	if pt := b & mqttPacketMask; pt != mqttPacketDisconnect {
		t.Fatalf("Expected DISCONNECT (%x), got %x", mqttPacketDisconnect, pt)
	}
	reason, err := r1.readByte("disconnect reason")
	if err != nil {
		t.Fatalf("Error reading disconnect reason: %v", err)
	}
	if reason != mqttReasonSessionTakenOver {
		t.Fatalf("Expected reason 0x%x (session taken over), got 0x%x", mqttReasonSessionTakenOver, reason)
	}
}

// A CONNECT whose remaining length does not match the bytes its fields actually
// consume (e.g. a lying properties length) must be rejected as malformed, not
// silently desync the packet stream.
func TestMQTTv5ConnectLengthMismatch(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	vh := newMQTTWriter(0)
	vh.WriteString(string(mqttProtoName))
	vh.WriteByte(mqttProtoLevel5)
	vh.WriteByte(mqttConnFlagCleanSession)
	vh.WriteUint16(0) // keep alive
	vh.WriteVarInt(0) // empty properties
	vh.WriteString("mismatch")
	vh.WriteByte(0) // trailing byte no CONNECT field accounts for
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketConnect)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())

	addr := net.JoinHostPort(o.MQTT.Host, fmt.Sprintf("%d", o.MQTT.Port))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Error dialing: %v", err)
	}
	defer c.Close()
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing connect: %v", err)
	}

	_, reason, _ := testMQTTReadConnAckV5(t, &mqttReader{reader: c})
	if reason != mqttReasonMalformedPacket {
		t.Fatalf("Expected reason 0x%x (malformed packet), got 0x%x", mqttReasonMalformedPacket, reason)
	}
}

// ---- PUBLISH property forwarding ----

// testMQTTv5PubPropsBlock builds a raw MQTT 5.0 PUBLISH properties block
// (var-int length prefix + body) exercising the forwardable property types.
func testMQTTv5PubPropsBlock() []byte {
	body := newMQTTWriter(0)
	body.WriteByte(mqttPropPayloadFormat)
	body.WriteByte(1)
	body.WriteByte(mqttPropContentType)
	body.WriteString("application/json")
	body.WriteByte(mqttPropResponseTopic)
	body.WriteString("resp/topic")
	body.WriteByte(mqttPropCorrelationData)
	body.WriteBytes([]byte("corr-1"))
	body.WriteByte(mqttPropUserProperty)
	body.WriteString("k1")
	body.WriteString("v1")
	body.WriteByte(mqttPropUserProperty)
	body.WriteString("k2")
	body.WriteString("v2")
	w := newMQTTWriter(0)
	w.WriteVarInt(body.Len())
	w.Write(body.Bytes())
	return w.Bytes()
}

// testMQTTCheckFwdProps asserts that p matches testMQTTv5PubPropsBlock.
func testMQTTCheckFwdProps(t testing.TB, p *mqttProperties) {
	t.Helper()
	if p == nil {
		t.Fatal("Expected forwarded properties, got none")
	}
	if p.contentType != "application/json" {
		t.Fatalf("content type: got %q", p.contentType)
	}
	if p.responseTopic != "resp/topic" {
		t.Fatalf("response topic: got %q", p.responseTopic)
	}
	if string(p.correlationData) != "corr-1" {
		t.Fatalf("correlation data: got %q", p.correlationData)
	}
	if !p.present[mqttPropPayloadFormat] || p.payloadFormat != 1 {
		t.Fatalf("payload format indicator: present=%v val=%v", p.present[mqttPropPayloadFormat], p.payloadFormat)
	}
	if len(p.user) != 2 || p.user[0].key != "k1" || p.user[0].value != "v1" ||
		p.user[1].key != "k2" || p.user[1].value != "v2" {
		t.Fatalf("user properties: got %+v", p.user)
	}
}

// testMQTTPubV5Props publishes a v5 PUBLISH with the given raw properties block
// (nil => empty), completing the QoS1/QoS2 sender handshake.
func testMQTTPubV5Props(t testing.TB, c net.Conn, r *mqttReader, qos byte, retain bool, pi uint16, topic string, payload, props []byte) {
	t.Helper()
	flags := qos << 1
	if retain {
		flags |= mqttPubFlagRetain
	}
	vh := newMQTTWriter(0)
	vh.WriteBytes([]byte(topic))
	if qos > 0 {
		vh.WriteUint16(pi)
	}
	if len(props) > 0 {
		vh.Write(props)
	} else {
		vh.WriteVarInt(0)
	}
	vh.Write(payload)
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketPub | flags)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing PUBLISH: %v", err)
	}
	switch qos {
	case 1:
		testMQTTReadPubAck(t, r, pi)
	case 2:
		testMQTTReadPIPacket(mqttPacketPubRec, t, r, pi)
		pubrel := [4]byte{mqttPacketPubRel | 0x2, 0x2, byte(pi >> 8), byte(pi)}
		if _, err := testMQTTWrite(c, pubrel[:]); err != nil {
			t.Fatalf("Error writing PUBREL: %v", err)
		}
		testMQTTReadPIPacket(mqttPacketPubComp, t, r, pi)
	}
}

// testMQTTReadPubV5Props reads a delivered v5 PUBLISH, validates topic/payload,
// acks a QoS1 delivery, and returns the parsed properties (nil if empty).
func testMQTTReadPubV5Props(t testing.TB, c net.Conn, r *mqttReader, expTopic string, expPayload []byte) *mqttProperties {
	t.Helper()
	b, pl := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketPub {
		t.Fatalf("Expected PUBLISH (%x), got %x", mqttPacketPub, pt)
	}
	start := r.pos
	qos := mqttGetQoS(b & mqttPacketFlagMask)
	topic, err := r.readBytes("topic", false)
	if err != nil {
		t.Fatalf("Error reading topic: %v", err)
	}
	if string(topic) != expTopic {
		t.Fatalf("Expected topic %q, got %q", expTopic, topic)
	}
	var pi uint16
	if qos > 0 {
		if pi, err = r.readUint16("pi"); err != nil {
			t.Fatalf("Error reading pi: %v", err)
		}
	}
	props, err := r.readProperties(mqttPropsContextPubOut)
	if err != nil {
		t.Fatalf("Error reading PUBLISH properties: %v", err)
	}
	payloadLen := pl - (r.pos - start)
	if payloadLen < 0 || r.pos+payloadLen > len(r.buf) {
		t.Fatalf("Invalid payload length %d", payloadLen)
	}
	got := r.buf[r.pos : r.pos+payloadLen]
	r.pos += payloadLen
	if string(got) != string(expPayload) {
		t.Fatalf("Expected payload %q, got %q", expPayload, got)
	}
	if qos == 1 {
		pa := [4]byte{mqttPacketPubAck, 0x2, byte(pi >> 8), byte(pi)}
		if _, err := testMQTTWrite(c, pa[:]); err != nil {
			t.Fatalf("Error writing PUBACK: %v", err)
		}
	}
	return props
}

// v5 PUBLISH properties are forwarded unaltered to a v5 subscriber, across the
// QoS0/1/2 publish paths (including QoS2 store + PUBREL replay).
func TestMQTTv5PublishPropertyForwarding(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	for _, pubQoS := range []byte{0, 1, 2} {
		t.Run(fmt.Sprintf("pubqos%d", pubQoS), func(t *testing.T) {
			topic := fmt.Sprintf("fwd/q%d", pubQoS)
			cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: fmt.Sprintf("fwdsub%d", pubQoS), cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer cs.Close()
			testMQTTReadConnAckV5(t, rs)
			testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: topic, opts: 1}})

			cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: fmt.Sprintf("fwdpub%d", pubQoS), cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer cp.Close()
			testMQTTReadConnAckV5(t, rp)
			testMQTTPubV5Props(t, cp, rp, pubQoS, false, 10, topic, []byte("payload"), testMQTTv5PubPropsBlock())

			props := testMQTTReadPubV5Props(t, cs, rs, topic, []byte("payload"))
			testMQTTCheckFwdProps(t, props)
		})
	}
}

// A Will must not inherit the properties of the client's last PUBLISH (they
// share c.mqtt.pp). The Will's own properties are not forwarded yet, so the
// delivered Will must carry an empty properties block.
func TestMQTTv5WillDoesNotLeakPublishProps(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wlsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "wl/t", opts: 0}})

	// Client with a Will publishes a property-bearing message, then dies
	// ungracefully so the Will fires.
	will := &mqttWill{topic: []byte("wl/t"), message: []byte("bye"), qos: 0}
	cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wlpub", cleanStart: true, will: will}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, rw)
	testMQTTPubV5Props(t, cw, rw, 0, false, 0, "other", []byte("x"), testMQTTv5PubPropsBlock())
	cw.Close()

	if props := testMQTTReadPubV5Props(t, cs, rs, "wl/t", []byte("bye")); props != nil {
		t.Fatalf("Will leaked publisher properties: %+v", props)
	}
}

// Retained v5 properties are persisted and replayed to a late v5 subscriber.
func TestMQTTv5RetainedPropertyForwarding(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "retpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, true, 20, "ret/topic", []byte("retained"), testMQTTv5PubPropsBlock())

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "retsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "ret/topic", opts: 1}})

	props := testMQTTReadPubV5Props(t, cs, rs, "ret/topic", []byte("retained"))
	testMQTTCheckFwdProps(t, props)
}

// A v5 publisher's properties must be stripped when delivering to a 3.1.1
// subscriber, and a 3.1.1 publisher must yield an empty properties block to a
// v5 subscriber.
func TestMQTTv5PropertyForwardingInterop(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	t.Run("v5 pub props to 3.1.1 sub are stripped", func(t *testing.T) {
		c311, r311 := testMQTTConnect(t, &mqttConnInfo{clientID: "sub311", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
		defer c311.Close()
		testMQTTCheckConnAck(t, r311, mqttConnAckRCConnectionAccepted, false)
		testMQTTSub(t, 1, c311, r311, []*mqttFilter{{filter: "interop/a", qos: 0}}, []byte{0})

		cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "pub5", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer cp.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, cp, rp, 0, false, 0, "interop/a", []byte("hello"), testMQTTv5PubPropsBlock())

		// A 3.1.1 reader parses the packet with no properties section; if props
		// leaked through, the payload would not match.
		testMQTTCheckPubMsg(t, c311, r311, "interop/a", 0, []byte("hello"))
	})

	t.Run("3.1.1 pub to v5 sub yields empty props", func(t *testing.T) {
		cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sub5", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer cs.Close()
		testMQTTReadConnAckV5(t, rs)
		testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "interop/b", opts: 1}})

		cp, rp := testMQTTConnect(t, &mqttConnInfo{clientID: "pub311", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
		defer cp.Close()
		testMQTTCheckConnAck(t, rp, mqttConnAckRCConnectionAccepted, false)
		testMQTTPublish(t, cp, rp, 0, false, false, "interop/b", 0, []byte("plain"))

		if props := testMQTTReadPubV5Props(t, cs, rs, "interop/b", []byte("plain")); props != nil {
			t.Fatalf("Expected no forwarded properties from a 3.1.1 publisher, got %+v", props)
		}
	})
}

// Retained-message encode/decode round-trips the properties block and stays
// backward compatible with stored messages that have none.
func TestMQTTv5RetainedMessagePropsEncodeDecode(t *testing.T) {
	subj := mqttRetainedMsgsStreamSubject + "a.b"
	props := testMQTTv5PubPropsBlock()

	rm := &mqttRetainedMsg{Topic: "a/b", Flags: mqttPubQos1 | mqttPubFlagRetain, Origin: "orig", Source: "src", Props: props, Msg: []byte("hello")}
	natsMsg, hlen := mqttEncodeRetainedMessage(rm)
	dec, err := mqttDecodeRetainedMessage(subj, natsMsg[:hlen], natsMsg[hlen:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(dec.Props) != string(props) {
		t.Fatalf("props round-trip mismatch: got %x want %x", dec.Props, props)
	}

	// No properties: must decode with empty Props (also the shape of older
	// stored messages).
	rm2 := &mqttRetainedMsg{Topic: "a/b", Flags: mqttPubQos1 | mqttPubFlagRetain, Msg: []byte("x")}
	natsMsg2, hlen2 := mqttEncodeRetainedMessage(rm2)
	dec2, err := mqttDecodeRetainedMessage(subj, natsMsg2[:hlen2], natsMsg2[hlen2:])
	if err != nil {
		t.Fatalf("decode (no props): %v", err)
	}
	if len(dec2.Props) != 0 {
		t.Fatalf("expected no props, got %x", dec2.Props)
	}
}

// mqttMakePropsBlock wraps a raw properties body with its var-int length prefix.
func mqttMakePropsBlock(body []byte) []byte {
	w := newMQTTWriter(0)
	w.WriteVarInt(len(body))
	w.Write(body)
	return w.Bytes()
}

// Only well-formed, forwardable property blocks survive validation; malformed
// blocks and blocks carrying Topic Alias or a Subscription Identifier are
// dropped so the server never emits a malformed/forbidden outbound PUBLISH.
func TestMQTTv5ValidateForwardProps(t *testing.T) {
	valid := testMQTTv5PubPropsBlock()
	topicAlias := mqttMakePropsBlock([]byte{mqttPropTopicAlias, 0x00, 0x01})
	subID := mqttMakePropsBlock([]byte{mqttPropSubscriptionID, 0x01})
	lyingLen := []byte{0x0a, 0x01}                      // says 10 bytes follow, only 1
	trailing := append(testMQTTv5PubPropsBlock(), 0xff) // valid block + junk

	for _, test := range []struct {
		name string
		in   []byte
		keep bool
	}{
		{"valid", valid, true},
		{"empty", nil, false},
		{"topic alias", topicAlias, false},
		{"subscription id", subID, false},
		{"lying length", lyingLen, false},
		{"trailing bytes", trailing, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			out := mqttValidateForwardProps(test.in)
			if test.keep && string(out) != string(test.in) {
				t.Fatalf("expected block kept unchanged, got %x", out)
			}
			if !test.keep && out != nil {
				t.Fatalf("expected block dropped (nil), got %x", out)
			}
		})
	}
}

// A client-to-server PUBLISH carrying a Subscription Identifier is a protocol
// error (spec5 [MQTT-3.3.4-6]); the server must reject it, not relay it.
func TestMQTTv5PublishSubscriptionIdRejected(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "subidpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)

	// v5 PUBLISH (QoS1) whose properties include a Subscription Identifier.
	props := mqttMakePropsBlock([]byte{mqttPropSubscriptionID, 0x01})
	vh := newMQTTWriter(0)
	vh.WriteBytes([]byte("foo"))
	vh.WriteUint16(1)
	vh.Write(props)
	vh.Write([]byte("x"))
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketPub | (1 << 1))
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing PUBLISH: %v", err)
	}

	// Server rejects: no PUBACK, connection is closed.
	if buf, err := testMQTTRead(c); err == nil {
		if pt := buf[0] & mqttPacketMask; pt == mqttPacketPubAck {
			t.Fatal("server acked a PUBLISH carrying a Subscription Identifier")
		}
	}
}

// A non-MQTT (NATS) publisher can set Nmqtt-Pub/Nmqtt-Props on a message an MQTT
// client is subscribed to. A crafted (malformed) Nmqtt-Props must be dropped so
// the v5 subscriber still receives a well-formed PUBLISH with no properties.
func TestMQTTv5ForwardPropsFromNATSPublisherValidated(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "injsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "inj/x", opts: 0}})

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()
	hdr := nats.Header{}
	hdr.Set(mqttNatsHeader, "0") // makes the delivery path parse MQTT metadata
	hdr.Set(mqttNatsHeaderProps, base64.StdEncoding.EncodeToString([]byte{0x0a, 0x01}))
	if err := nc.PublishMsg(&nats.Msg{Subject: "inj.x", Header: hdr, Data: []byte("hello")}); err != nil {
		t.Fatalf("nats publish: %v", err)
	}
	nc.Flush()

	if props := testMQTTReadPubV5Props(t, cs, rs, "inj/x", []byte("hello")); props != nil {
		t.Fatalf("Expected injected malformed props to be dropped, got %+v", props)
	}
}

// A Will PUBLISH must carry the Will's own properties (Payload Format, Content
// Type, Response Topic, Correlation Data, User Properties), not none and not
// the client's last PUBLISH's. Spec5 [3.1.3.2].
func TestMQTTv5WillForwardsOwnProps(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wpsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "wp/t", opts: 0}})

	will := &mqttWill{topic: []byte("wp/t"), message: []byte("bye"), qos: 0}
	// willProps is the raw properties body: strip the length varint (one byte,
	// the block is short) from the shared test block.
	willProps := testMQTTv5PubPropsBlock()[1:]
	cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wppub", cleanStart: true, will: will, willProps: willProps}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, rw)
	// Die ungracefully so the Will fires.
	cw.Close()

	props := testMQTTReadPubV5Props(t, cs, rs, "wp/t", []byte("bye"))
	testMQTTCheckFwdProps(t, props)
}

// A legacy JSON-encoded retained message must have its Props validated like the
// header-encoded path: a forbidden block (e.g. Topic Alias) is dropped rather
// than forwarded verbatim to subscribers.
func TestMQTTv5RetainedJSONFallbackPropsValidated(t *testing.T) {
	badProps := newMQTTWriter(0)
	badProps.WriteByte(mqttPropTopicAlias)
	badProps.WriteUint16(5)
	jm, err := json.Marshal(&mqttRetainedMsg{Topic: "foo", Msg: []byte("m"), Props: badProps.Bytes()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rm, err := mqttDecodeRetainedMessage(mqttRetainedMsgsStreamSubject+"foo", nil, jm)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rm.Props != nil {
		t.Fatalf("Expected forbidden props to be dropped, got %v", rm.Props)
	}
}

// ---- Receive Maximum ----

// mqttV5ConnPropsReceiveMax returns a CONNECT properties body carrying a
// Receive Maximum property (0x21).
func mqttV5ConnPropsReceiveMax(n uint16) []byte {
	b := newMQTTWriter(0)
	b.WriteByte(mqttPropReceiveMaximum)
	b.WriteUint16(n)
	return b.Bytes()
}

func testMQTTSessionReceiveMax(t testing.TB, s *Server, clientID string) uint16 {
	t.Helper()
	c := testMQTTGetClient(t, s, clientID)
	sess := c.mqtt.sess
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.rmax
}

// The client's Receive Maximum is recorded on the session (0 for 3.1.1), and
// bounds the number of unacknowledged QoS1 PUBLISH the server has in flight:
// a second message is held until the first is acked and then redelivered.
func TestMQTTv5ReceiveMaximum(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	o.MQTT.AckWait = time.Second // keep redelivery of the held message fast
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// 3.1.1 client imposes no limit.
	c311, r311 := testMQTTConnect(t, &mqttConnInfo{clientID: "rm311", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer c311.Close()
	testMQTTCheckConnAck(t, r311, mqttConnAckRCConnectionAccepted, false)
	if got := testMQTTSessionReceiveMax(t, s, "rm311"); got != 0 {
		t.Fatalf("expected rmax=0 for a 3.1.1 client, got %d", got)
	}

	// v5 subscriber with Receive Maximum = 1.
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rmsub", cleanStart: true, props: mqttV5ConnPropsReceiveMax(1)}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	if got := testMQTTSessionReceiveMax(t, s, "rmsub"); got != 1 {
		t.Fatalf("expected rmax=1, got %d", got)
	}
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "rm/t", opts: 1}})

	// Publisher sends two QoS1 messages back to back.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rmpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, false, 1, "rm/t", []byte("m1"), nil)
	testMQTTPubV5Props(t, cp, rp, 1, false, 2, "rm/t", []byte("m2"), nil)

	// Only the first is delivered; the second is held while one is unacked.
	// testMQTTReadPublishV5 does not ack.
	_, pi := testMQTTReadPublishV5(t, rs, "rm/t", []byte("m1"))
	testMQTTExpectNothing(t, rs)

	// Ack the first; the held message is redelivered once a slot frees.
	pa := [4]byte{mqttPacketPubAck, 0x2, byte(pi >> 8), byte(pi)}
	if _, err := testMQTTWrite(cs, pa[:]); err != nil {
		t.Fatalf("Error writing PUBACK: %v", err)
	}
	testMQTTReadPublishV5(t, rs, "rm/t", []byte("m2"))
}

// mqttV5PropsSessionExpiryReceiveMax builds a CONNECT properties body with a
// Session Expiry Interval and, when rmax > 0, a Receive Maximum.
func mqttV5PropsSessionExpiryReceiveMax(secs uint32, rmax uint16) []byte {
	w := newMQTTWriter(0)
	w.WriteByte(mqttPropSessionExpiry)
	w.WriteUint32(secs)
	if rmax > 0 {
		w.WriteByte(mqttPropReceiveMaximum)
		w.WriteUint16(rmax)
	}
	return w.Bytes()
}

// On resume the server re-sends unacknowledged QoS 1/2 messages, but must not
// exceed the resumed connection's Receive Maximum. Spec5 [MQTT-3.3.4-9].
func TestMQTTv5ReceiveMaximumResumeCap(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	o.MQTT.AckWait = 3 * testMQTTTimeout // keep un-NAK'd messages from redelivering during the test
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// First connection: no Receive Maximum, so several QoS1 messages are delivered
	// unacked and accumulate as pending.
	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rmr", cleanStart: false,
		props: mqttV5PropsSessionExpiryReceiveMax(300, 0)}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, r)
	testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "rmr/t", opts: 1}})

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rmrpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	for i, m := range []string{"m1", "m2", "m3"} {
		testMQTTPubV5Props(t, cp, rp, 1, false, uint16(i+1), "rmr/t", []byte(m), nil)
		testMQTTReadPublishV5(t, r, "rmr/t", []byte(m))
	}
	c.Close()

	// Resume with Receive Maximum = 1: only one message may be re-sent now; the
	// rest wait for AckWait (set very long above).
	c2, r2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rmr", cleanStart: false,
		props: mqttV5PropsSessionExpiryReceiveMax(300, 1)}, o.MQTT.Host, o.MQTT.Port)
	defer c2.Close()
	if sp, _, _ := testMQTTReadConnAckV5(t, r2); !sp {
		t.Fatal("expected session present on resume")
	}
	testMQTTReadPublishV5(t, r2, "rmr/t", []byte("m1"))
	testMQTTExpectNothing(t, r2)
}

// A QoS1/2 message reaped by its Message Expiry TTL while the client was offline
// can neither be redelivered nor acked; on resume its pending entry must be
// released so it does not leak a Receive Maximum slot. Spec5 [3.3.2.3.3].
func TestMQTTv5MessageExpiryPendingReconciledOnResume(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	o.MQTT.AckWait = 3 * testMQTTTimeout
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cprobe, rprobe := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "h5probe", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cprobe.Close()
	testMQTTReadConnAckV5(t, rprobe)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "h5", cleanStart: false,
		props: mqttV5PropsSessionExpiryReceiveMax(300, 0)}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, r)
	testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "h5/t", opts: 1}})

	// Two QoS1 messages delivered unacked, so both are pending.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "h5pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, false, 1, "h5/t", []byte("m1"), nil)
	testMQTTPubV5Props(t, cp, rp, 1, false, 2, "h5/t", []byte("m2"), nil)
	testMQTTReadPublishV5(t, r, "h5/t", []byte("m1"))
	testMQTTReadPublishV5(t, r, "h5/t", []byte("m2"))
	c.Close()

	asm := testMQTTGetAccountSessionManager(t, s, "h5probe")
	hash := getHash("h5")
	asm.mu.RLock()
	sess := asm.sessByHash[hash]
	asm.mu.RUnlock()
	require_NotNil(t, sess)
	sess.mu.Lock()
	var loSeq, hiSeq uint64
	for _, ack := range sess.pendingPublish {
		if loSeq == 0 || ack.sseq < loSeq {
			loSeq = ack.sseq
		}
		if ack.sseq > hiSeq {
			hiSeq = ack.sseq
		}
	}
	pendBefore := len(sess.pendingPublish)
	sess.mu.Unlock()
	require_True(t, pendBefore == 2 && loSeq > 0 && hiSeq > loSeq)

	// Simulate the Message Expiry TTL reaping only the LATER message, leaving a
	// hole above the stream's first sequence (the earlier message survives).
	require_NoError(t, asm.jsa.deleteMsg(mqttStreamName, hiSeq, true))

	// Resume: the pending entry for the reaped (mid-stream) message must be
	// released; the surviving message's entry stays.
	c2, r2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "h5", cleanStart: false,
		props: mqttV5PropsSessionExpiryReceiveMax(300, 0)}, o.MQTT.Host, o.MQTT.Port)
	defer c2.Close()
	testMQTTReadConnAckV5(t, r2)
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		if _, ok := findPendingBySeq(sess, hiSeq); ok {
			return fmt.Errorf("expected reaped entry (seq %d) released", hiSeq)
		}
		if _, ok := findPendingBySeq(sess, loSeq); !ok {
			return fmt.Errorf("surviving entry (seq %d) was wrongly dropped", loSeq)
		}
		return nil
	})
}

// findPendingBySeq reports the packet id tracking the given stream sequence.
// Session lock held on entry.
func findPendingBySeq(sess *mqttSession, sseq uint64) (uint16, bool) {
	for pi, ack := range sess.pendingPublish {
		if ack.sseq == sseq {
			return pi, true
		}
	}
	return 0, false
}

func TestMQTTv5ReceiveMaximumQoS2(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	o.MQTT.AckWait = time.Second
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// v5 subscriber, Receive Maximum = 1, QoS2 subscription.
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rm2sub", cleanStart: true, props: mqttV5ConnPropsReceiveMax(1)}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "rm2/t", opts: 2}})

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rm2pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 2, false, 1, "rm2/t", []byte("m1"), nil)
	testMQTTPubV5Props(t, cp, rp, 2, false, 2, "rm2/t", []byte("m2"), nil)

	// m1 delivered; m2 held at the cap.
	_, pi := testMQTTReadPublishV5(t, rs, "rm2/t", []byte("m1"))
	testMQTTExpectNothing(t, rs)

	// PUBREC moves m1 to the awaiting-PUBCOMP state, which still counts against
	// the Receive Maximum: the server sends PUBREL but must keep m2 held.
	testMQTTSendPIPacket(mqttPacketPubRec, t, cs, pi)
	testMQTTReadPIPacket(mqttPacketPubRel, t, rs, pi)
	testMQTTExpectNothing(t, rs)

	// PUBCOMP frees the slot; m2 is now delivered.
	testMQTTSendPIPacket(mqttPacketPubComp, t, cs, pi)
	testMQTTReadPublishV5(t, rs, "rm2/t", []byte("m2"))
}

func TestMQTTSessionDropUnredeliverableRetained(t *testing.T) {
	// A retained (QoS1/2) delivery is tracked with no JetStream backing (empty
	// jsAckSubject); it cannot be redelivered, so it must be released on resume
	// rather than leaking a Receive Maximum slot. JS-backed entries stay.
	sess := &mqttSession{
		pendingPublish: map[uint16]*mqttPending{
			1: {jsDur: "d", sseq: 10, jsAckSubject: "$JS.ACK.x"},
			2: {}, // retained, no backing
		},
	}
	sess.dropUnredeliverableRetained()
	if _, ok := sess.pendingPublish[2]; ok {
		t.Fatal("expected retained entry (empty jsAckSubject) to be dropped")
	}
	if _, ok := sess.pendingPublish[1]; !ok {
		t.Fatal("expected JS-backed entry to be kept")
	}
}

// trackPublish must report started=true for a redelivery (a PI already tracked
// for the stream sequence), reusing the same PI. mqttDeliverMsgCbQoS12 relies on
// this to resend an already-started delivery on Message Expiry rather than
// dropping it. An end-to-end expiry test is not deterministic here: the
// JetStream per-message TTL equals the Message Expiry Interval, so the message
// is reaped from the stream at the same time it logically expires.
func TestMQTTSessionTrackPublishStarted(t *testing.T) {
	sess := &mqttSession{maxp: 10}
	const dur = "S_C"
	// $JS.ACK.<stream>.<consumer>.<deliveries>.<streamseq>.<consumerseq>.<ts>.<pending>
	pi1, dup1, started1 := sess.trackPublish(dur, "$JS.ACK.S.C.1.100.1.0.0")
	if pi1 == 0 || dup1 || started1 {
		t.Fatalf("first delivery: pi=%d dup=%v started=%v", pi1, dup1, started1)
	}
	// Redelivery of the same stream sequence (deliveries=2).
	pi2, dup2, started2 := sess.trackPublish(dur, "$JS.ACK.S.C.2.100.2.0.0")
	if pi2 != pi1 || !dup2 || !started2 {
		t.Fatalf("redelivery: pi=%d (want %d) dup=%v started=%v", pi2, pi1, dup2, started2)
	}
}

// A Receive Maximum of 0 is a protocol error (spec5 [3.1.2.11.3]); the CONNECT
// is rejected with a CONNACK carrying reason 0x82 (Protocol Error).
func TestMQTTv5ReceiveMaximumZeroRejected(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rmzero", cleanStart: true, props: mqttV5ConnPropsReceiveMax(0)}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	_, reason, _ := testMQTTReadConnAckV5(t, r)
	if reason != mqttReasonProtocolError {
		t.Fatalf("Expected reason 0x%x (protocol error), got 0x%x", mqttReasonProtocolError, reason)
	}
}

// testMQTTReadAnyPublishV5 reads one v5 PUBLISH without asserting its topic and
// returns (qos, topic, payload). Does not ack.
func testMQTTReadAnyPublishV5(t testing.TB, r *mqttReader) (byte, string, []byte) {
	t.Helper()
	b, pl := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketPub {
		t.Fatalf("Expected PUBLISH (%x), got %x", mqttPacketPub, pt)
	}
	start := r.pos
	qos := mqttGetQoS(b & mqttPacketFlagMask)
	topic, err := r.readBytes("topic", false)
	if err != nil {
		t.Fatalf("Error reading topic: %v", err)
	}
	if qos > 0 {
		if _, err = r.readUint16("pi"); err != nil {
			t.Fatalf("Error reading pi: %v", err)
		}
	}
	if _, err = r.readProperties(mqttPropsContextPubOut); err != nil {
		t.Fatalf("Error reading PUBLISH properties: %v", err)
	}
	payloadLen := pl - (r.pos - start)
	got := r.buf[r.pos : r.pos+payloadLen]
	r.pos += payloadLen
	return qos, string(topic), append([]byte(nil), got...)
}

// Retained QoS>0 replay is bounded by the effective cap (MaxAckPending capped by
// Receive Maximum): with Receive Maximum=1, only one matching retained message
// is delivered as QoS1; the rest are downgraded to QoS0 (delivered, not counted
// against the in-flight limit).
func TestMQTTv5RetainedReceiveMaximum(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// Publish three retained QoS1 messages under a common prefix.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "retpub2", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	topics := []string{"ret/a", "ret/b", "ret/c"}
	for i, tp := range topics {
		testMQTTPubV5Props(t, cp, rp, 1, true, uint16(i+1), tp, []byte("v"), nil)
	}

	// Subscribe QoS1 with Receive Maximum = 1.
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "retsub2", cleanStart: true, props: mqttV5ConnPropsReceiveMax(1)}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "ret/#", opts: 1}})

	seen := map[string]bool{}
	qos1 := 0
	for range topics {
		qos, tp, _ := testMQTTReadAnyPublishV5(t, rs)
		seen[tp] = true
		if qos > 0 {
			qos1++
		}
	}
	if len(seen) != len(topics) {
		t.Fatalf("Expected all %d retained topics delivered, got %v", len(topics), seen)
	}
	// At most the effective cap (1) may be in flight as QoS>0; the rest are QoS0.
	if qos1 > 1 {
		t.Fatalf("Expected at most 1 retained message as QoS>0 under Receive Maximum=1, got %d", qos1)
	}
}

// With Receive Maximum=1 the server must pace QoS1 delivery without reordering:
// each message arrives only after the previous one is acked, in publish order,
// and without waiting out AckWait (which is left at its 30s default here, so a
// drop-at-cap would make this test time out).
func TestMQTTv5ReceiveMaximumOrdering(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "ordsub", cleanStart: true, props: mqttV5ConnPropsReceiveMax(1)}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "ord/t", opts: 1}})
	testMQTTFlush(t, cs, nil, rs)

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "ordpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	for i := 1; i <= 3; i++ {
		testMQTTPublishV5(t, cp, 1, uint16(i), "ord/t", []byte{byte('0' + i)})
		testMQTTReadPubAck(t, rp, uint16(i))
	}

	for i := 1; i <= 3; i++ {
		_, pi := testMQTTReadPublishV5(t, rs, "ord/t", []byte{byte('0' + i)})
		pa := [4]byte{mqttPacketPubAck, 0x2, byte(pi >> 8), byte(pi)}
		if _, err := testMQTTWrite(cs, pa[:]); err != nil {
			t.Fatalf("Error writing PUBACK: %v", err)
		}
	}
}

// mqttV5ConnPropsMaxPacketSize returns a CONNECT properties body carrying a
// Maximum Packet Size property (0x27).
func mqttV5ConnPropsMaxPacketSize(n uint32) []byte {
	b := newMQTTWriter(0)
	b.WriteByte(mqttPropMaxPacketSize)
	b.WriteUint32(n)
	return b.Bytes()
}

// testMQTTConnMaxPacketSize returns the Maximum Packet Size recorded on the
// connection for clientID (0 when none was advertised).
func testMQTTConnMaxPacketSize(t testing.TB, s *Server, clientID string) uint32 {
	t.Helper()
	c := testMQTTGetClient(t, s, clientID)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mqtt.maxPacketSize
}

// testMQTTSessionNumPending returns the number of unacknowledged QoS1/2 PUBLISH
// currently in flight for clientID's session.
func testMQTTSessionNumPending(t testing.TB, s *Server, clientID string) int {
	t.Helper()
	c := testMQTTGetClient(t, s, clientID)
	sess := c.mqtt.sess
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return len(sess.pendingPublish)
}

// The client's Maximum Packet Size is recorded on the connection (0 for a 3.1.1
// client or when not sent). An outbound QoS1 PUBLISH that would exceed it is not
// sent; instead it is discarded and the delivery is completed so it does not
// occupy an in-flight slot forever (the pending set drains back to empty), while
// the connection keeps working for messages within the limit. Spec5 [3.1.2.11.4].
func TestMQTTv5MaximumPacketSize(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// 3.1.1 client imposes no limit.
	c311, r311 := testMQTTConnect(t, &mqttConnInfo{clientID: "mp311", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer c311.Close()
	testMQTTCheckConnAck(t, r311, mqttConnAckRCConnectionAccepted, false)
	if got := testMQTTConnMaxPacketSize(t, s, "mp311"); got != 0 {
		t.Fatalf("expected maxPacketSize=0 for a 3.1.1 client, got %d", got)
	}

	// v5 subscriber with a small Maximum Packet Size.
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "mpsub", cleanStart: true, props: mqttV5ConnPropsMaxPacketSize(50)}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	if got := testMQTTConnMaxPacketSize(t, s, "mpsub"); got != 50 {
		t.Fatalf("expected maxPacketSize=50, got %d", got)
	}
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "mp/t", opts: 1}})

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "mppub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)

	// An oversized QoS1 PUBLISH is not delivered...
	large := []byte(strings.Repeat("x", 200))
	testMQTTPubV5Props(t, cp, rp, 1, false, 1, "mp/t", large, nil)
	testMQTTExpectNothing(t, rs)

	// ...and it is completed rather than left occupying an in-flight slot: the
	// subscriber's pending-publish set drains back to empty.
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		if n := testMQTTSessionNumPending(t, s, "mpsub"); n != 0 {
			return fmt.Errorf("expected 0 pending publishes after discard, got %d", n)
		}
		return nil
	})

	// A PUBLISH within the limit is delivered and ackable.
	small := []byte("ok")
	testMQTTPubV5Props(t, cp, rp, 1, false, 2, "mp/t", small, nil)
	testMQTTReadPubV5Props(t, cs, rs, "mp/t", small) // reads and acks the QoS1 delivery
}

// A QoS0 PUBLISH exceeding the client's Maximum Packet Size is silently dropped
// (there is nothing to ack); one within the limit is delivered.
func TestMQTTv5MaximumPacketSizeQoS0(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "mpq0sub", cleanStart: true, props: mqttV5ConnPropsMaxPacketSize(50)}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "mp/q0", opts: 0}})

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "mpq0pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)

	testMQTTPubV5Props(t, cp, rp, 0, false, 0, "mp/q0", []byte(strings.Repeat("x", 200)), nil)
	testMQTTExpectNothing(t, rs)

	small := []byte("ok")
	testMQTTPubV5Props(t, cp, rp, 0, false, 0, "mp/q0", small, nil)
	testMQTTReadPubV5Props(t, cs, rs, "mp/q0", small)
}

// A 3.1.1 subscriber advertises no Maximum Packet Size (maxPacketSize == 0), so
// the limit never applies: a large message is delivered unchanged.
func TestMQTTv5MaximumPacketSize311Unaffected(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnect(t, &mqttConnInfo{clientID: "mp311sub", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTCheckConnAck(t, rs, mqttConnAckRCConnectionAccepted, false)
	testMQTTSub(t, 1, cs, rs, []*mqttFilter{{filter: "mp/t", qos: 0}}, []byte{0})

	cp, rp := testMQTTConnect(t, &mqttConnInfo{clientID: "mp311pub", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTCheckConnAck(t, rp, mqttConnAckRCConnectionAccepted, false)

	large := []byte(strings.Repeat("x", 200))
	testMQTTPublish(t, cp, rp, 0, false, false, "mp/t", 0, large)
	testMQTTCheckPubMsg(t, cs, rs, "mp/t", 0, large)
}

// A Maximum Packet Size of 0 is a protocol error (spec5 [3.1.2.11.4]); the
// CONNECT is rejected with a CONNACK carrying reason 0x82 (Protocol Error).
func TestMQTTv5MaximumPacketSizeZeroRejected(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "mpzero", cleanStart: true, props: mqttV5ConnPropsMaxPacketSize(0)}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	_, reason, _ := testMQTTReadConnAckV5(t, r)
	if reason != mqttReasonProtocolError {
		t.Fatalf("Expected reason 0x%x (protocol error), got 0x%x", mqttReasonProtocolError, reason)
	}
}

// Retained-message replay on subscribe frames its own PUBLISH and has a guard
// separate from the live-delivery path (serializeRetainedMsgsForSub): a retained
// message exceeding the subscriber's Maximum Packet Size is skipped, while a
// within-limit retained message on the same subscription is delivered.
func TestMQTTv5RetainedMaximumPacketSize(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// Publish two retained QoS1 messages under a common prefix: one oversized,
	// one within the subscriber's future limit.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "retmppub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, true, 1, "retmp/big", []byte(strings.Repeat("x", 200)), nil)
	testMQTTPubV5Props(t, cp, rp, 1, true, 2, "retmp/small", []byte("ok"), nil)

	// Subscribe (QoS1) with a small Maximum Packet Size covering both retained
	// topics. Only the within-limit message is replayed; the oversized one is
	// skipped, so exactly one PUBLISH arrives regardless of replay order.
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "retmpsub", cleanStart: true, props: mqttV5ConnPropsMaxPacketSize(50)}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "retmp/#", opts: 1}})

	testMQTTReadPubV5Props(t, cs, rs, "retmp/small", []byte("ok")) // reads and acks the QoS1 delivery
	testMQTTExpectNothing(t, rs)
}

// mqttV5PropsWithExpiry builds a v5 PUBLISH properties block carrying a Message
// Expiry Interval alongside a few other forwardable properties, so tests can
// assert the interval is adjusted without the rest being disturbed.
func mqttV5PropsWithExpiry(me uint32) []byte {
	body := newMQTTWriter(0)
	body.WriteByte(mqttPropPayloadFormat)
	body.WriteByte(1)
	body.WriteByte(mqttPropMessageExpiry)
	body.WriteUint32(me)
	body.WriteByte(mqttPropContentType)
	body.WriteString("text/plain")
	body.WriteByte(mqttPropUserProperty)
	body.WriteString("mk")
	body.WriteString("mv")
	return mqttMakePropsBlock(body.Bytes())
}

// The Message Expiry Interval can be located and rewritten inside a raw v5
// properties block without disturbing the other properties, and blocks without
// one are left untouched.
func TestMQTTv5MessageExpiryPropsHelpers(t *testing.T) {
	block := mqttV5PropsWithExpiry(100)

	off := mqttPropValueOffset(block, mqttPropMessageExpiry)
	if off < 0 {
		t.Fatal("expected to find the message expiry offset")
	}
	if got := binary.BigEndian.Uint32(block[off:]); got != 100 {
		t.Fatalf("value at offset is %d, want 100", got)
	}
	if got, ok := mqttMessageExpiry(block); !ok || got != 100 {
		t.Fatalf("mqttMessageExpiry: got %d present=%v, want 100/true", got, ok)
	}
	if got := mqttMessageExpiryTTL(block); got != 100 {
		t.Fatalf("mqttMessageExpiryTTL: got %d want 100", got)
	}

	// Rewriting must copy (not mutate the input) and preserve every other prop.
	orig := append([]byte(nil), block...)
	out := mqttSetMessageExpiry(block, 42)
	if string(block) != string(orig) {
		t.Fatal("mqttSetMessageExpiry mutated its input")
	}
	if &out[0] == &block[0] {
		t.Fatal("expected mqttSetMessageExpiry to return a copy")
	}
	r := &mqttReader{}
	r.reset(out)
	p, err := r.readProperties(mqttPacketPub)
	if err != nil || r.hasMore() {
		t.Fatalf("re-parse rewritten block: err=%v hasMore=%v", err, r.hasMore())
	}
	if !p.present[mqttPropMessageExpiry] || p.messageExpiry != 42 {
		t.Fatalf("message expiry not updated: present=%v val=%d", p.present[mqttPropMessageExpiry], p.messageExpiry)
	}
	if !p.present[mqttPropPayloadFormat] || p.payloadFormat != 1 {
		t.Fatal("payload format indicator was lost")
	}
	if p.contentType != "text/plain" {
		t.Fatalf("content type was lost: %q", p.contentType)
	}
	if len(p.user) != 1 || p.user[0].key != "mk" || p.user[0].value != "mv" {
		t.Fatalf("user property was lost: %+v", p.user)
	}

	// A block with no Message Expiry Interval: nothing found, no-op rewrite, and
	// no TTL. Absent must be distinguishable from an explicit 0.
	noexp := testMQTTv5PubPropsBlock()
	if mqttPropValueOffset(noexp, mqttPropMessageExpiry) != -1 {
		t.Fatal("did not expect a message expiry offset")
	}
	if got, ok := mqttMessageExpiry(noexp); ok || got != 0 {
		t.Fatalf("mqttMessageExpiry on absent: got %d present=%v, want 0/false", got, ok)
	}
	if got := mqttMessageExpiryTTL(noexp); got != 0 {
		t.Fatalf("mqttMessageExpiryTTL on absent: got %d want 0 (no TTL)", got)
	}
	if same := mqttSetMessageExpiry(noexp, 5); &same[0] != &noexp[0] {
		t.Fatal("expected the same slice back when there is no expiry to set")
	}

	// An explicit interval of 0 is present (expire immediately) and must map to a
	// 1s storage TTL, never to "no TTL".
	zero := mqttV5PropsWithExpiry(0)
	if got, ok := mqttMessageExpiry(zero); !ok || got != 0 {
		t.Fatalf("mqttMessageExpiry on explicit 0: got %d present=%v, want 0/true", got, ok)
	}
	if got := mqttMessageExpiryTTL(zero); got != 1 {
		t.Fatalf("mqttMessageExpiryTTL on explicit 0: got %d want 1", got)
	}
}

// A retained message published with a Message Expiry Interval round-trips its
// absolute deadline through encode/decode and carries a JetStream per-message
// TTL; a retained message without one carries neither.
func TestMQTTv5RetainedMessageExpiryEncodeDecode(t *testing.T) {
	subj := mqttRetainedMsgsStreamSubject + "a.b"
	props := mqttV5PropsWithExpiry(3600)
	exp := time.Now().Add(time.Hour)

	rm := &mqttRetainedMsg{Topic: "a/b", Flags: mqttPubQos1 | mqttPubFlagRetain, Props: props, Msg: []byte("hi"), expires: exp}
	natsMsg, hlen := mqttEncodeRetainedMessage(rm)
	// The TTL must round up: for a ~3599.99s remainder it must be 3600s, not a
	// truncated 3599s that would delete the copy early.
	if ttl := string(getHeader(JSMessageTTL, natsMsg[:hlen])); ttl != "3600s" {
		t.Fatalf("expected %s header of 3600s (ceiling), got %q", JSMessageTTL, ttl)
	}
	dec, err := mqttDecodeRetainedMessage(subj, natsMsg[:hlen], natsMsg[hlen:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.expires.IsZero() {
		t.Fatal("expiry deadline was not preserved")
	}
	if !dec.expires.Equal(time.Unix(0, exp.UnixNano())) {
		t.Fatalf("expiry deadline drift: got %v want %v", dec.expires, exp)
	}

	// No expiry: neither the TTL header nor a decoded deadline.
	rm2 := &mqttRetainedMsg{Topic: "a/b", Flags: mqttPubQos1 | mqttPubFlagRetain, Msg: []byte("x")}
	nm2, hl2 := mqttEncodeRetainedMessage(rm2)
	if strings.Contains(string(nm2[:hl2]), JSMessageTTL+":") {
		t.Fatal("did not expect a TTL header without expiry")
	}
	dec2, err := mqttDecodeRetainedMessage(subj, nm2[:hl2], nm2[hl2:])
	if err != nil {
		t.Fatalf("decode (no expiry): %v", err)
	}
	if !dec2.expires.IsZero() {
		t.Fatal("expected a zero expiry deadline")
	}
}

// A retained message replayed to a late v5 subscriber carries the Message Expiry
// Interval reduced by the time it has been waiting in the server. Spec5 [3.3.2.3.3].
func TestMQTTv5RetainedMessageExpiryDecrement(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rexp-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, true, 21, "rexp/topic", []byte("retained"), mqttV5PropsWithExpiry(1000))

	// Let the message wait in the server for a couple of seconds.
	time.Sleep(2100 * time.Millisecond)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rexp-sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "rexp/topic", opts: 1}})

	props := testMQTTReadPubV5Props(t, cs, rs, "rexp/topic", []byte("retained"))
	if props == nil || !props.present[mqttPropMessageExpiry] {
		t.Fatalf("expected a message expiry interval, got %+v", props)
	}
	if me := props.messageExpiry; me == 0 || me >= 1000 || me < 990 {
		t.Fatalf("message expiry not decremented as expected: got %d (want ~998)", me)
	}
	// The rest of the forwarded properties must be intact.
	if props.contentType != "text/plain" {
		t.Fatalf("forwarded content type lost: %q", props.contentType)
	}
}

// A retained message whose Message Expiry Interval has elapsed is no longer
// delivered to a new subscriber. Spec5 [3.3.2.3.3].
func TestMQTTv5RetainedMessageExpires(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rexp2-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, true, 22, "rexp2/topic", []byte("gone"), mqttV5PropsWithExpiry(1))

	time.Sleep(2200 * time.Millisecond)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rexp2-sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "rexp2/topic", opts: 1}})
	testMQTTExpectNothing(t, rs)
}

// A QoS2 PUBLISH carrying a Message Expiry Interval completes its store/PUBREL
// handshake (the dedup hold stream has no per-message TTL, so the interval must
// not be written there) and is forwarded to a v5 subscriber with its properties
// intact. Spec5 [3.3.2.3.3].
func TestMQTTv5QoS2MessageExpiryForwarded(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "q2exp-sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "q2exp/topic", opts: 2}})

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "q2exp-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	// A successful QoS2 handshake here proves the hold-stream store was not
	// rejected by a stray TTL header.
	testMQTTPubV5Props(t, cp, rp, 2, false, 40, "q2exp/topic", []byte("q2"), mqttV5PropsWithExpiry(3600))

	props := testMQTTReadPubV5Props(t, cs, rs, "q2exp/topic", []byte("q2"))
	if props == nil || !props.present[mqttPropMessageExpiry] {
		t.Fatalf("expected a forwarded message expiry interval, got %+v", props)
	}
	// Delivered promptly, so the interval is essentially unchanged.
	if me := props.messageExpiry; me == 0 || me > 3600 || me < 3590 {
		t.Fatalf("unexpected forwarded message expiry: got %d (want ~3600)", me)
	}
	if props.contentType != "text/plain" {
		t.Fatalf("forwarded content type lost: %q", props.contentType)
	}
}

// A stored QoS1 message whose Message Expiry Interval elapses while its
// subscriber is offline must not be delivered on reconnect. Spec5 [3.3.2.3.3].
func TestMQTTv5QoS1MessageExpires(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// A persistent session subscribes, then goes offline. In MQTT 5.0 a session
	// persists past disconnect only with a non-zero Session Expiry Interval (an
	// absent interval defaults to 0, ending the session at close). Spec5 [3.1.2.11.2].
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "qexp-sub", cleanStart: false,
		props: mqttV5ConnPropsSessionExpiry(300)}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "qexp/topic", opts: 1}})
	cs.Close()

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "qexp-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, false, 30, "qexp/topic", []byte("gone"), mqttV5PropsWithExpiry(1))

	time.Sleep(2200 * time.Millisecond)

	// Reconnect the persistent session: the expired message must not arrive.
	cs2, rs2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "qexp-sub", cleanStart: false,
		props: mqttV5ConnPropsSessionExpiry(300)}, o.MQTT.Host, o.MQTT.Port)
	defer cs2.Close()
	if sp, _, _ := testMQTTReadConnAckV5(t, rs2); !sp {
		t.Fatal("expected the session to be present on reconnect")
	}
	testMQTTExpectNothing(t, rs2)
}

// A retained message published with an explicit Message Expiry Interval of 0
// expires immediately and must not be delivered to a later subscriber. This
// distinguishes an explicit 0 (expire now) from an absent interval (never
// expires). Spec5 [3.3.2.3.3].
func TestMQTTv5RetainedMessageExpiryZeroImmediate(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "r0-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, true, 23, "r0/topic", []byte("boom"), mqttV5PropsWithExpiry(0))

	time.Sleep(200 * time.Millisecond)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "r0-sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "r0/topic", opts: 1}})
	testMQTTExpectNothing(t, rs)
}

// A QoS2 PUBLISH ages against its Message Expiry Interval while it waits for the
// PUBREL. If the interval elapses before the sender releases the message, the
// server must not forward it (the clock does not restart at PUBREL). Spec5
// [3.3.2.3.3].
func TestMQTTv5QoS2ExpiryAgesDuringPubRel(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "q2age-sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "q2age/topic", opts: 2}})

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "q2age-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)

	// Send the QoS2 PUBLISH (expiry 1s) and its PUBREC, then stall before PUBREL
	// so the message expires while held on the server.
	pi := uint16(41)
	vh := newMQTTWriter(0)
	vh.WriteBytes([]byte("q2age/topic"))
	vh.WriteUint16(pi)
	vh.Write(mqttV5PropsWithExpiry(1))
	vh.Write([]byte("stale"))
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketPub | (2 << 1))
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	if _, err := testMQTTWrite(cp, w.Bytes()); err != nil {
		t.Fatalf("Error writing PUBLISH: %v", err)
	}
	testMQTTReadPIPacket(mqttPacketPubRec, t, rp, pi)

	time.Sleep(1500 * time.Millisecond)

	pubrel := [4]byte{mqttPacketPubRel | 0x2, 0x2, byte(pi >> 8), byte(pi)}
	if _, err := testMQTTWrite(cp, pubrel[:]); err != nil {
		t.Fatalf("Error writing PUBREL: %v", err)
	}
	testMQTTReadPIPacket(mqttPacketPubComp, t, rp, pi)

	// Expired while awaiting PUBREL: the subscriber must receive nothing.
	testMQTTExpectNothing(t, rs)
}

// A stored (QoS 1/2) message published with an explicit Message Expiry Interval
// of 0 expires immediately and must not be forwarded to a subscriber, even when
// onward delivery would otherwise happen within the same second. Covers the
// QoS1 delivery and QoS2 PUBREL-release paths. Spec5 [3.3.2.3.3].
func TestMQTTv5StoredMessageExpiryZeroNotDelivered(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	for _, qos := range []byte{1, 2} {
		t.Run(fmt.Sprintf("qos%d", qos), func(t *testing.T) {
			topic := fmt.Sprintf("z0/q%d", qos)
			cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: fmt.Sprintf("z0sub%d", qos), cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer cs.Close()
			testMQTTReadConnAckV5(t, rs)
			testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: topic, opts: qos}})

			cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: fmt.Sprintf("z0pub%d", qos), cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer cp.Close()
			testMQTTReadConnAckV5(t, rp)
			// A successful handshake with no onward delivery is the assertion.
			testMQTTPubV5Props(t, cp, rp, qos, false, 50, topic, []byte("x"), mqttV5PropsWithExpiry(0))

			testMQTTExpectNothing(t, rs)
		})
	}
}

// The max_payload preflight must account for the Nats-TTL header a Message
// Expiry Interval adds to the stored message, and must not double-count the QoS2
// hold-stream subject headers together with that TTL header (they never coexist
// on the same stored message). Sizes are derived from the production sizing so
// the boundary is exact. Spec5 [3.3.2.3.3].
func TestMQTTv5MessageExpiryMaxPayload(t *testing.T) {
	props := mqttV5PropsWithExpiry(60)
	payload := bytes.Repeat([]byte("x"), 2000)

	// Build the mqttPublish exactly as the server does for a PUBLISH to "foo".
	subj, err := mqttTopicToNATSPubSubject([]byte("foo"))
	if err != nil {
		t.Fatalf("subject conversion: %v", err)
	}
	pp := &mqttPublish{topic: []byte("foo"), subject: subj, msg: payload, sz: len(payload), props: props}
	// v5 delivered messages carry the Nmqtt-Origin header (the No Local marker, a
	// fixed-length HMAC tag, so its size is the same for every client here). The
	// QoS2 dedup-hold copy carries none. Match production so the boundary is exact.
	origin := mqttOriginMarker([]byte("k"), "id", "subj", []byte("p"))
	// This publish is not retained, so no Nmqtt-Ret header on either form.
	delivery := mqttComputeNatsMsgSize(pp, false, mqttMessageExpiryTTL(props), origin, false) // QoS0/1 store form, QoS2 delivery form
	hold := mqttComputeNatsMsgSize(pp, true, 0, _EMPTY_, false)                               // QoS2 dedup-hold form

	sendPub := func(t *testing.T, c net.Conn, qos byte) {
		vh := newMQTTWriter(0)
		vh.WriteBytes([]byte("foo"))
		vh.WriteUint16(7)
		vh.Write(props)
		vh.Write(payload)
		w := newMQTTWriter(0)
		w.WriteByte(mqttPacketPub | (qos << 1))
		w.WriteVarInt(vh.Len())
		w.Write(vh.Bytes())
		if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
			t.Fatalf("Error writing PUBLISH: %v", err)
		}
	}

	// One byte below the full stored size: accepted only if the TTL header were
	// (wrongly) omitted from the check, so this asserts the TTL is counted.
	t.Run("qos1 rejected when TTL header exceeds the limit", func(t *testing.T) {
		o := testMQTTDefaultOptionsV5()
		o.MaxPayload = int32(delivery - 1)
		s := testMQTTRunServer(t, o)
		defer testMQTTShutdownServer(s)
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "mp-rej", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		sendPub(t, c, 1)
		testMQTTExpectDisconnect(t, c)
	})

	t.Run("qos1 accepted at exactly the full stored size", func(t *testing.T) {
		o := testMQTTDefaultOptionsV5()
		o.MaxPayload = int32(delivery)
		s := testMQTTRunServer(t, o)
		defer testMQTTShutdownServer(s)
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "mp-acc", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTPubV5Props(t, c, r, 1, false, 7, "foo", payload, props) // completes with PUBACK
	})

	// max_payload set to the larger of the two actual QoS2 forms. The message
	// fits; only the old buggy sum (hold headers + TTL header) would reject it.
	t.Run("qos2 not over-rejected", func(t *testing.T) {
		maxp := hold
		if delivery > maxp {
			maxp = delivery
		}
		o := testMQTTDefaultOptionsV5()
		o.MaxPayload = int32(maxp)
		s := testMQTTRunServer(t, o)
		defer testMQTTShutdownServer(s)
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "mp-q2", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTPubV5Props(t, c, r, 2, false, 7, "foo", payload, props) // full QoS2 handshake completes
	})
}

// A message published with Message Expiry Interval = 0 expires immediately and
// must not be delivered to ANY subscriber, whatever its protocol level or QoS.
// Spec5 [3.3.2.3.3].
func TestMQTTv5MessageExpiryZeroAllProtos(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// 3.1.1 subscriber at QoS1 (JetStream-backed delivery path).
	c311, r311 := testMQTTConnect(t, &mqttConnInfo{clientID: "mei311", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer c311.Close()
	testMQTTCheckConnAck(t, r311, mqttConnAckRCConnectionAccepted, false)
	testMQTTSub(t, 1, c311, r311, []*mqttFilter{{filter: "mei/z", qos: 1}}, []byte{1})
	testMQTTFlush(t, c311, nil, r311)

	// v5 subscriber at QoS0 (direct delivery path).
	cs0, rs0 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "meiq0", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs0.Close()
	testMQTTReadConnAckV5(t, rs0)
	testMQTTSubV5(t, cs0, rs0, 1, []mqttV5SubFilter{{topic: "mei/z", opts: 0}})
	testMQTTFlush(t, cs0, nil, rs0)

	// v5 publisher sends QoS1 with Message Expiry Interval = 0.
	props := newMQTTWriter(0)
	props.WriteByte(mqttPropMessageExpiry)
	props.WriteUint32(0)
	block := newMQTTWriter(0)
	block.WriteVarInt(props.Len())
	block.Write(props.Bytes())
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "meipub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, false, 1, "mei/z", []byte("x"), block.Bytes())

	testMQTTExpectNothing(t, r311)
	testMQTTExpectNothing(t, rs0)
}

// In degraded mode (the retained stream refused AllowMsgTTL) the encoded
// retained message must omit the Nats-TTL header, which the stream would
// reject, while keeping the expiry deadline so delivery-side expiry still
// works.
func TestMQTTv5RetainedMessageEncodeNoTTL(t *testing.T) {
	rm := &mqttRetainedMsg{Topic: "t", Msg: []byte("m"), expires: time.Now().Add(time.Minute)}
	full, _ := mqttEncodeRetainedMessageTTL(rm, true)
	if !bytes.Contains(full, []byte(JSMessageTTL)) {
		t.Fatal("Expected a Nats-TTL header with withTTL=true")
	}
	deg, hdr := mqttEncodeRetainedMessageTTL(rm, false)
	if bytes.Contains(deg, []byte(JSMessageTTL)) {
		t.Fatal("Expected no Nats-TTL header with withTTL=false")
	}
	if !bytes.Contains(deg, []byte(mqttNatsRetainedMessageExpiry)) {
		t.Fatal("Expected the expiry deadline header to be kept")
	}
	dec, err := mqttDecodeRetainedMessage(mqttRetainedMsgsStreamSubject+"t", deg[:hdr], deg[hdr:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.expires.IsZero() {
		t.Fatal("Expected the decoded message to keep its expiry deadline")
	}
}

// In degraded mode (the messages stream refused AllowMsgTTL) a stored QoS1/2
// PUBLISH must omit the Nats-TTL header JetStream would reject; the Message
// Expiry properties are still stored and forwarded for delivery-side checks.
func TestMQTTv5MessagesStreamDegradedNoTTL(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "degsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "deg/t", opts: 1}})
	testMQTTFlush(t, cs, nil, rs)

	meiBlock := func() []byte {
		p := newMQTTWriter(0)
		p.WriteByte(mqttPropMessageExpiry)
		p.WriteUint32(600)
		b := newMQTTWriter(0)
		b.WriteVarInt(p.Len())
		b.Write(p.Bytes())
		return b.Bytes()
	}

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "degpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	// Normal mode: the stored copy carries the per-message TTL. Fetch it
	// before the subscriber acks (this is an interest stream).
	testMQTTPubV5Props(t, cp, rp, 1, false, 1, "deg/t", []byte("m1"), meiBlock())
	msg, err := js.GetLastMsg(mqttStreamName, "$MQTT.msgs.deg.t")
	if err != nil {
		t.Fatalf("get stored message: %v", err)
	}
	if msg.Header.Get(JSMessageTTL) == "" {
		t.Fatal("Expected a Nats-TTL header on the stored message in normal mode")
	}
	testMQTTReadPubV5Props(t, cs, rs, "deg/t", []byte("m1"))

	// Degraded mode, as set when enabling AllowMsgTTL on the stream failed.
	asm := testMQTTGetAccountSessionManager(t, s, "degpub")
	asm.msgsStreamNoTTL = true

	testMQTTPubV5Props(t, cp, rp, 1, false, 2, "deg/t", []byte("m2"), meiBlock())
	msg, err = js.GetLastMsg(mqttStreamName, "$MQTT.msgs.deg.t")
	if err != nil {
		t.Fatalf("get stored message: %v", err)
	}
	if string(msg.Data) != "m2" {
		t.Fatalf("Expected the degraded-mode message to be stored, got %q", msg.Data)
	}
	if v := msg.Header.Get(JSMessageTTL); v != "" {
		t.Fatalf("Expected no Nats-TTL header on the stored message in degraded mode, got %q", v)
	}
	props := testMQTTReadPubV5Props(t, cs, rs, "deg/t", []byte("m2"))
	if props == nil || !props.present[mqttPropMessageExpiry] {
		t.Fatal("Expected the Message Expiry property to still be forwarded")
	}
}

// A delayed Will must carry the Will's own forwardable properties when it
// eventually fires, matching the immediate-publish path. Spec5 [3.1.3.2].
func TestMQTTv5WillDelayForwardsOwnProps(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wdpsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "wdp/t", opts: 0}})
	testMQTTFlush(t, cs, nil, rs)

	will := &mqttWill{topic: []byte("wdp/t"), message: []byte("bye"), qos: 0}
	// Will Delay plus the shared forwardable-props block (strip its length varint).
	willProps := append(mqttV5WillDelayProps(1), testMQTTv5PubPropsBlock()[1:]...)
	cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wdppub", cleanStart: true, will: will,
		willProps: willProps, props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, rw)
	// Abrupt close: the Will is deferred by the delay, then fires.
	cw.Close()

	props := testMQTTReadPubV5Props(t, cs, rs, "wdp/t", []byte("bye"))
	testMQTTCheckFwdProps(t, props)
}

// A delayed Will pending at shutdown is persisted with the session record and
// re-armed on restart, so it still fires. Spec5 [3.1.3.2.2] whichever-first.
// Covered for both a durable session and a clean-start one (whose Will rides a
// minimal record created just for it), and with a generated server name (the
// standalone default), which changes across restarts.
func TestMQTTv5WillDelaySurvivesRestart(t *testing.T) {
	for _, test := range []struct {
		name       string
		cleanStart bool
	}{
		{"durable session", false},
		{"clean start with session expiry", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := testMQTTDefaultOptionsV5()
			// Standalone servers may run without an explicit server name; the
			// generated one differs after a restart.
			o.ServerName = _EMPTY_
			s := testMQTTRunServer(t, o)
			defer testMQTTShutdownRestartedServer(&s)

			// Retained Will so the post-restart subscriber gets it even if it
			// fires before the subscription lands.
			will := &mqttWill{topic: []byte("wdr/t"), message: []byte("late-bye"), qos: 0, retain: true}
			cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wdrpub", cleanStart: test.cleanStart, will: will,
				willProps: mqttV5WillDelayProps(3), props: mqttV5ConnPropsSessionExpiry(300)}, o.MQTT.Host, o.MQTT.Port)
			testMQTTReadConnAckV5(t, rw)
			cw.Close()

			// Wait for the pending Will to land in the persisted session record.
			nc, js := jsClientConnect(t, s)
			sessSubj := mqttSessStreamSubjectPrefix + getHash("wdrpub")
			checkFor(t, 2*time.Second, 50*time.Millisecond, func() error {
				m, err := js.GetLastMsg(mqttSessStreamName, sessSubj)
				if err != nil {
					return err
				}
				if !bytes.Contains(m.Data, []byte(`"will"`)) {
					return fmt.Errorf("session record has no pending will yet")
				}
				return nil
			})
			nc.Close()

			// Restart on the same store.
			dir := strings.TrimSuffix(s.JetStreamConfig().StoreDir, JetStreamStoreDir)
			s.Shutdown()
			o.Port = -1
			o.MQTT.Port = -1
			o.StoreDir = dir
			s = testMQTTRunServer(t, o)

			// The first MQTT connect creates the account session manager, whose
			// sweep re-arms the persisted Will.
			cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "wdrsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer cs.Close()
			testMQTTReadConnAckV5(t, rs)
			testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "wdr/t", opts: 0}})

			testMQTTReadPublishV5(t, rs, "wdr/t", []byte("late-bye"))

			// Once fired, the persisted Will must be gone (for a clean session,
			// its carrier record with it) so it cannot fire again.
			nc2, js2 := jsClientConnect(t, s)
			defer nc2.Close()
			checkFor(t, 2*time.Second, 50*time.Millisecond, func() error {
				m, err := js2.GetLastMsg(mqttSessStreamName, sessSubj)
				if err != nil {
					return nil // record deleted entirely: fine (clean session)
				}
				if bytes.Contains(m.Data, []byte(`"will"`)) {
					return fmt.Errorf("session record still has the fired will")
				}
				return nil
			})
		})
	}
}

// testMQTTHasPendingExpiry reports whether a session-expiry timer is armed for
// targetClientID on the account session manager (reached via a live client sharing
// the account). Checking a specific client, rather than a total count, keeps the
// assertion robust against sessions left pending by other subtests.
func testMQTTHasPendingExpiry(t testing.TB, s *Server, liveClientID, targetClientID string) bool {
	t.Helper()
	c := testMQTTGetClient(t, s, liveClientID)
	asm := c.mqtt.asm
	asm.mu.Lock()
	defer asm.mu.Unlock()
	_, ok := asm.pendingExpiries[getHash(targetClientID)]
	return ok
}

// testMQTTSessionExpiry returns the effective Session Expiry Interval and the
// derived clean flag recorded on the session of a connected client.
func testMQTTSessionExpiry(t testing.TB, s *Server, clientID string) (uint32, bool) {
	t.Helper()
	c := testMQTTGetClient(t, s, clientID)
	sess := c.mqtt.sess
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.expiryInterval, sess.clean
}

// mqttV5DisconnectSessionExpiry crafts a v5 DISCONNECT carrying a Session Expiry
// Interval property, used to update the session expiry at disconnect time.
func mqttV5DisconnectSessionExpiry(reason byte, secs uint32) []byte {
	props := newMQTTWriter(0)
	props.WriteByte(mqttPropSessionExpiry)
	props.WriteUint32(secs)
	vh := newMQTTWriter(0)
	vh.WriteByte(reason)
	vh.WriteVarInt(props.Len())
	vh.Write(props.Bytes())
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketDisconnect)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	return w.Bytes()
}

// testMQTTSessionRecordExists reports whether a session record for
// targetClientID is present in the sessions stream, via the account session
// manager of a live client sharing the account.
func testMQTTSessionRecordExists(t testing.TB, s *Server, liveClientID, targetClientID string) bool {
	t.Helper()
	c := testMQTTGetClient(t, s, liveClientID)
	asm := c.mqtt.asm
	_, err := asm.jsa.loadSessionMsg(asm.domainTk, getHash(targetClientID))
	if err != nil {
		if isErrorOtherThan(err, JSNoMessageFoundErr) {
			t.Fatalf("Error loading session record for %q: %v", targetClientID, err)
		}
		return false
	}
	return true
}

// A finite Session Expiry Interval must survive a server restart: the disconnect
// time is persisted with the session record and the deadlines are re-armed (or
// executed, if overdue) by a sweep when the account session manager is recreated.
// Sessions that never expire are left untouched. Spec5 [3.1.2.11.2].
func TestMQTTv5SessionExpiryPersistedAcrossRestart(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownRestartedServer(&s)

	connectAndSub := func(id string, props []byte) {
		t.Helper()
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: id, cleanStart: true, props: props},
			o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "sepr/" + id, opts: 1}})
		c.Close()
	}
	// Long finite interval: must be re-armed after the restart.
	connectAndSub("seprl", mqttV5ConnPropsSessionExpiry(300))
	// Short finite interval: overdue by the time the server is back up.
	connectAndSub("seprs", mqttV5ConnPropsSessionExpiry(2))
	// Never expires: must not be swept.
	connectAndSub("seprn", mqttV5ConnPropsSessionExpiry(mqttSessionNeverExpire))

	// A live probe to reach the account session manager. Confirm both finite
	// timers are armed, which also means the disconnect deadlines were persisted.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seprobe", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, rp)
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		for _, id := range []string{"seprl", "seprs"} {
			if !testMQTTHasPendingExpiry(t, s, "seprobe", id) {
				return fmt.Errorf("expected a pending expiry for %q", id)
			}
		}
		return nil
	})
	cp.Close()

	// Restart the server on the same store: all in-memory timers are lost.
	dir := strings.TrimSuffix(s.JetStreamConfig().StoreDir, JetStreamStoreDir)
	s.Shutdown()
	o.Port = -1
	o.MQTT.Port = -1
	o.StoreDir = dir
	s = testMQTTRunServer(t, o)

	// The sweep runs when the first MQTT connect recreates the account session
	// manager.
	cp2, rp2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seprobe", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp2.Close()
	testMQTTReadConnAckV5(t, rp2)

	// The long session's timer is re-armed; the overdue one is cleaned up (its
	// record deleted); the never-expiring one is left alone.
	checkFor(t, 4*time.Second, 15*time.Millisecond, func() error {
		if !testMQTTHasPendingExpiry(t, s, "seprobe", "seprl") {
			return fmt.Errorf("expected the pending expiry for seprl to be re-armed")
		}
		if testMQTTSessionRecordExists(t, s, "seprobe", "seprs") {
			return fmt.Errorf("expected the overdue seprs session record to be deleted")
		}
		return nil
	})
	if testMQTTHasPendingExpiry(t, s, "seprobe", "seprn") {
		t.Fatal("did not expect a pending expiry for the never-expiring session")
	}
	if !testMQTTSessionRecordExists(t, s, "seprobe", "seprn") {
		t.Fatal("expected the never-expiring session record to be present")
	}

	// And the client-visible outcome: the long and never-expiring sessions resume,
	// the overdue one is gone.
	for _, tc := range []struct {
		id    string
		props []byte
		sp    bool
	}{
		{"seprl", mqttV5ConnPropsSessionExpiry(300), true},
		{"seprs", nil, false},
		{"seprn", mqttV5ConnPropsSessionExpiry(mqttSessionNeverExpire), true},
	} {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: tc.id, props: tc.props}, o.MQTT.Host, o.MQTT.Port)
		sp, _, _ := testMQTTReadConnAckV5(t, r)
		c.Close()
		if sp != tc.sp {
			t.Fatalf("expected session-present=%v for %q, got %v", tc.sp, tc.id, sp)
		}
	}
}

// A stale remote session-persist ack (an older stream sequence than the local
// session's) must not cancel the local expiry timer; a newer one is a takeover
// and must.
func TestMQTTv5SessionExpiryStalePersistAck(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seprobe3", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sestale", cleanStart: true,
		props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, r)
	c.Close()
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		if !testMQTTHasPendingExpiry(t, s, "seprobe3", "sestale") {
			return fmt.Errorf("expected a pending expiry for sestale")
		}
		return nil
	})

	asm := testMQTTGetAccountSessionManager(t, s, "seprobe3")
	hash := getHash("sestale")
	asm.mu.RLock()
	sess := asm.sessByHash[hash]
	asm.mu.RUnlock()
	require_NotNil(t, sess)
	sess.mu.Lock()
	seq := sess.seq
	sess.mu.Unlock()

	// Deliver a crafted remote persist ack to the callback.
	deliverAck := func(ackSeq uint64) {
		t.Helper()
		b, err := json.Marshal(&JSPubAckResponse{PubAck: &PubAck{Stream: mqttSessStreamName, Sequence: ackSeq}})
		require_NoError(t, err)
		subject := mqttJSARepliesPrefix + "remoteid." + mqttJSASessPersist + "." + hash + ".reply"
		// pc is only used for msgParts; a fresh client has no header parse state.
		asm.processSessionPersist(nil, &client{}, nil, subject, _EMPTY_, append(b, CR_LF...))
	}

	// Stale ack: timer and session must survive.
	deliverAck(seq - 1)
	if !testMQTTHasPendingExpiry(t, s, "seprobe3", "sestale") {
		t.Fatal("expected the pending expiry to survive a stale persist ack")
	}

	// Newer ack: remote takeover, timer cancelled and session dropped.
	deliverAck(seq + 1)
	if testMQTTHasPendingExpiry(t, s, "seprobe3", "sestale") {
		t.Fatal("expected the pending expiry cancelled by a newer persist ack")
	}
	asm.mu.RLock()
	_, still := asm.sessByHash[hash]
	asm.mu.RUnlock()
	if still {
		t.Fatal("expected the session removed by a newer persist ack")
	}
}

// When a stale in-memory expiry timer fires and the persisted record has been
// bumped past our sequence, our copy is stale, so expireSession drops it and lets
// the authoritative record-based path decide: a connected record
// (DisconnectedAt==0, a takeover elsewhere) is left intact; a disconnected but
// not-yet-due record is re-armed rather than cleaned early; a due one is cleaned
// up (using the record's own sequence). Spec5 [3.1.2.11.2].
func TestMQTTv5SessionExpiryStaleTimerRecordState(t *testing.T) {
	for _, test := range []struct {
		name        string
		disconnAt   func() int64 // newer record's DisconnectedAt (0 == connected)
		wantRecord  bool         // record still present after the timer fired
		wantReArmed bool         // a new expiry timer was armed
	}{
		{"connected takeover keeps state", func() int64 { return 0 }, true, false},
		{"not-yet-due record is re-armed", func() int64 { return time.Now().Unix() }, true, true},
		{"due record is cleaned up", func() int64 { return time.Now().Unix() - 200 }, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := testMQTTDefaultOptionsV5()
			s := testMQTTRunServer(t, o)
			defer testMQTTShutdownServer(s)

			// Probe keeps the account session manager alive.
			cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seh4probe", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer cp.Close()
			testMQTTReadConnAckV5(t, rp)

			// Persistent session with a long Session Expiry Interval; subscribe
			// (creates a consumer), then disconnect so an expiry timer is armed and
			// the session is kept with sess.c == nil.
			c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seh4", cleanStart: false,
				props: mqttV5ConnPropsSessionExpiry(100)}, o.MQTT.Host, o.MQTT.Port)
			testMQTTReadConnAckV5(t, r)
			testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "seh4/t", opts: 1}})
			c.Close()
			checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
				if !testMQTTHasPendingExpiry(t, s, "seh4probe", "seh4") {
					return fmt.Errorf("expected a pending expiry for seh4")
				}
				return nil
			})

			asm := testMQTTGetAccountSessionManager(t, s, "seh4probe")
			hash := getHash("seh4")

			// Rewrite the record (bumping the stream sequence past ours) as another
			// server would, while this server still holds the session and its timer.
			ps := mqttPersistedSession{Origin: "remote", ID: "seh4", ExpiryInterval: 100, DisconnectedAt: test.disconnAt()}
			b, err := json.Marshal(&ps)
			require_NoError(t, err)
			_, err = asm.jsa.storeSessionMsg(asm.domainTk, hash, 0, b)
			require_NoError(t, err)

			// The stale timer fires.
			asm.expireSession(s, hash)

			recordPresent := func() bool {
				_, err := asm.jsa.loadSessionMsg(asm.domainTk, hash)
				return err == nil
			}
			if test.wantRecord {
				require_True(t, recordPresent())
			} else {
				// Cleanup deletes the record asynchronously.
				checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
					if recordPresent() {
						return fmt.Errorf("expected the session record to be deleted")
					}
					return nil
				})
			}
			if got := testMQTTHasPendingExpiry(t, s, "seh4probe", "seh4"); got != test.wantReArmed {
				t.Fatalf("re-armed=%v, want %v", got, test.wantReArmed)
			}
		})
	}
}

// An overdue session must not be resumed even when its own client is the first
// MQTT connect after a restart, i.e. when the reconnect races (and beats) the
// async startup sweep: the restore path checks the deadline synchronously.
func TestMQTTv5SessionExpiryExpiredFirstReconnect(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownRestartedServer(&s)

	// QoS2 subscriber-side receive: PUBLISH -> PUBREC -> PUBREL -> PUBCOMP. The
	// handshake makes the server create the session's PUBREL durable.
	recvQoS2 := func(c net.Conn, r *mqttReader, payload []byte) {
		t.Helper()
		qos, pi := testMQTTReadPublishV5(t, r, "se/first", payload)
		if qos != 2 {
			t.Fatalf("expected QoS2 delivery, got %v", qos)
		}
		testMQTTSendPIPacket(mqttPacketPubRec, t, c, pi)
		testMQTTReadPIPacket(mqttPacketPubRel, t, r, pi)
		testMQTTSendPIPacket(mqttPacketPubComp, t, c, pi)
	}

	cpub, rpub := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sefpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cpub.Close()
	testMQTTReadConnAckV5(t, rpub)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sefirst", cleanStart: true,
		props: mqttV5ConnPropsSessionExpiry(1)}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, r)
	testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "se/first", opts: 2}})
	// Receive one QoS2 message so the PUBREL durable exists in the old session.
	testMQTTPubV5Props(t, cpub, rpub, 2, false, 10, "se/first", []byte("m1"), nil)
	recvQoS2(c, r, []byte("m1"))
	c.Close()

	// Wait for the disconnect deadline to be persisted (the timer is armed after
	// the save) before shutting down.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seprobe2", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, rp)
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		if !testMQTTHasPendingExpiry(t, s, "seprobe2", "sefirst") {
			return fmt.Errorf("expected a pending expiry for sefirst")
		}
		return nil
	})
	cp.Close()
	cpub.Close()

	// Restart on the same store, and make sure the session is overdue.
	dir := strings.TrimSuffix(s.JetStreamConfig().StoreDir, JetStreamStoreDir)
	s.Shutdown()
	time.Sleep(1500 * time.Millisecond)
	o.Port = -1
	o.MQTT.Port = -1
	o.StoreDir = dir
	s = testMQTTRunServer(t, o)

	// First MQTT connect is the expired client itself: no session present.
	c2, r2 := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "sefirst",
		props: mqttV5ConnPropsSessionExpiry(1)}, o.MQTT.Host, o.MQTT.Port, 3)
	defer c2.Close()
	if sp, _, _ := testMQTTReadConnAckV5(t, r2); sp {
		t.Fatal("expected session-present=false for an expired session on first reconnect")
	}

	// Immediately exercise QoS2 again: the fresh session recreates the same
	// deterministic PUBREL durable; the expired cleanup must not delete it.
	testMQTTSubV5(t, c2, r2, 1, []mqttV5SubFilter{{topic: "se/first", opts: 2}})
	cpub2, rpub2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sefpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cpub2.Close()
	testMQTTReadConnAckV5(t, rpub2)
	testMQTTPubV5Props(t, cpub2, rpub2, 2, false, 11, "se/first", []byte("m2"), nil)
	recvQoS2(c2, r2, []byte("m2"))
}

// The MQTT 5.0 Session Expiry Interval controls how long a session survives after
// the network connection closes: 0 ends it at close, a finite value keeps it for
// that many seconds (then it is cleaned up), and it is orthogonal to Clean Start.
// A DISCONNECT may update the interval. Spec5 [3.1.2.11.2], [3.14.2.2.2].
func TestMQTTv5SessionExpiry(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// A probe client kept connected for the whole test so the account session
	// manager is reachable via testMQTTGetClient after a target disconnects.
	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seprobe", cleanStart: true,
		props: mqttV5ConnPropsSessionExpiry(0)}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)

	t.Run("zero expiry ends session at close", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sez", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "se/z", opts: 1}})
		if exp, clean := testMQTTSessionExpiry(t, s, "sez"); exp != 0 || !clean {
			t.Fatalf("expected expiry=0 clean=true, got expiry=%d clean=%v", exp, clean)
		}
		c.Close()
		// Reconnect (clean start=0): the session must be gone (session present=0).
		c2, r2 := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "sez"}, o.MQTT.Host, o.MQTT.Port, 3)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); sp {
			t.Fatal("expected session-present=false after a zero-expiry session closed")
		}
	})

	t.Run("finite expiry survives and reconnect resumes", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sef", cleanStart: true,
			props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "se/f", opts: 0}})
		c.Close()

		// The session outlives the connection: a timer is armed and the session is
		// still tracked.
		checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
			if !testMQTTHasPendingExpiry(t, s, "seprobe", "sef") {
				return fmt.Errorf("expected a pending expiry for sef")
			}
			return nil
		})

		// Reconnect within the window: session present and the pending expiry
		// cancelled.
		c2, r2 := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "sef",
			props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port, 3)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); !sp {
			t.Fatal("expected session-present=true on reconnect within the expiry window")
		}
		checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
			if testMQTTHasPendingExpiry(t, s, "seprobe", "sef") {
				return fmt.Errorf("expected pending expiry for sef cancelled")
			}
			return nil
		})
	})

	t.Run("expiry fires and cleans up the session", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seexp", cleanStart: true,
			props: mqttV5ConnPropsSessionExpiry(1)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "se/exp", opts: 1}})
		c.Close()
		checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
			if !testMQTTHasPendingExpiry(t, s, "seprobe", "seexp") {
				return fmt.Errorf("expected a pending expiry for seexp")
			}
			return nil
		})

		// The 1s timer fires and cleans up the session state: the record is
		// deleted and the pending timer is consumed.
		checkFor(t, 4*time.Second, 50*time.Millisecond, func() error {
			if testMQTTSessionRecordExists(t, s, "seprobe", "seexp") {
				return fmt.Errorf("expected the seexp session record to be deleted")
			}
			return nil
		})
		if testMQTTHasPendingExpiry(t, s, "seprobe", "seexp") {
			t.Fatal("expected pending expiry for seexp removed after firing")
		}

		// The session state is gone: a clean-start=0 reconnect reports no session.
		c2, r2 := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "seexp"}, o.MQTT.Host, o.MQTT.Port, 3)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); sp {
			t.Fatal("expected session-present=false after the session expired")
		}
	})

	t.Run("clean start with non-zero expiry is durable", func(t *testing.T) {
		// Clean Start=1 (fresh session now) but Session Expiry>0 (keep it after
		// disconnect): the session must be durable, not ephemeral.
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sed", cleanStart: true,
			props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "se/d", opts: 0}})
		if exp, clean := testMQTTSessionExpiry(t, s, "sed"); exp != 30 || clean {
			t.Fatalf("expected expiry=30 clean=false (durable), got expiry=%d clean=%v", exp, clean)
		}
		c.Close()
		// Reconnect with clean start=0 resumes the durable session.
		c2, r2 := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "sed",
			props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port, 3)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); !sp {
			t.Fatal("expected session-present=true resuming a clean-start durable session")
		}
	})

	t.Run("disconnect overrides expiry to zero", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seo", cleanStart: true,
			props: mqttV5ConnPropsSessionExpiry(30)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "se/o", opts: 1}})
		// A DISCONNECT lowering the interval to 0 ends the session at close.
		if _, err := testMQTTWrite(c, mqttV5DisconnectSessionExpiry(mqttReasonSuccess, 0)); err != nil {
			t.Fatalf("Error writing DISCONNECT: %v", err)
		}
		c.Close()
		c2, r2 := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "seo"}, o.MQTT.Host, o.MQTT.Port, 3)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); sp {
			t.Fatal("expected session-present=false after DISCONNECT lowered expiry to 0")
		}
	})

	t.Run("disconnect cannot raise expiry from zero", func(t *testing.T) {
		// Spec5 [3.14.2.2.2]: raising a zero CONNECT interval on DISCONNECT is a
		// Protocol Error; we ignore the override and still end the session at close.
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "seg", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5(t, c, r, 1, []mqttV5SubFilter{{topic: "se/g", opts: 1}})
		if _, err := testMQTTWrite(c, mqttV5DisconnectSessionExpiry(mqttReasonSuccess, 30)); err != nil {
			t.Fatalf("Error writing DISCONNECT: %v", err)
		}
		c.Close()
		c2, r2 := testMQTTConnectRetryV5(t, &mqttV5ConnInfo{clientID: "seg"}, o.MQTT.Host, o.MQTT.Port, 3)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); sp {
			t.Fatal("expected session-present=false: a 0->non-zero DISCONNECT override must be ignored")
		}
	})

	t.Run("will delay is capped by session expiry", func(t *testing.T) {
		cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sewsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer cs.Close()
		testMQTTReadConnAckV5(t, rs)
		testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "se/will", opts: 0}})

		// Will Delay Interval 10s but Session Expiry Interval 1s: the Will must fire
		// when the session ends (~1s), not at 10s. Spec5 [3.1.3.2.2].
		will := &mqttWill{topic: []byte("se/will"), message: []byte("bye"), qos: 0}
		cw, rw := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sewill", cleanStart: true, will: will,
			willProps: mqttV5WillDelayProps(10), props: mqttV5ConnPropsSessionExpiry(1)}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, rw)
		cw.Close()

		// Bound the wait well under the 10s Will Delay so an uncapped delay fails.
		cs.SetReadDeadline(time.Now().Add(5 * time.Second))
		testMQTTReadPublishV5(t, rs, "se/will", []byte("bye"))
		cs.SetReadDeadline(time.Time{})
	})
}

// A reconnect that beats a late expiry timer to an overdue in-memory session
// must not resume it: the session is discarded, like on the record-restore
// path. Spec5 [3.1.2.11.2].
func TestMQTTv5SessionExpiryOverdueInMemoryResume(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// Auxiliary connected client to reach the account session manager.
	ca, ra := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "odraux", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer ca.Close()
	testMQTTReadConnAckV5(t, ra)

	// Durable v5 session with a subscription and a finite expiry.
	c1, r1 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "odr", props: mqttV5ConnPropsSessionExpiry(120)}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, r1)
	testMQTTSubV5(t, c1, r1, 1, []mqttV5SubFilter{{topic: "odr/t", opts: 1}})
	c1.Close()

	// Wait for the disconnect to be recorded, then simulate a late expiry
	// timer: backdate the deadline past due and drop the armed timer.
	asm := testMQTTGetAccountSessionManager(t, s, "odraux")
	idHash := getHash("odr")
	var sess *mqttSession
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		asm.mu.RLock()
		sess = asm.sessByHash[idHash]
		asm.mu.RUnlock()
		if sess == nil {
			return fmt.Errorf("session not in memory")
		}
		sess.mu.Lock()
		defer sess.mu.Unlock()
		if sess.disconnectedAt == 0 {
			return fmt.Errorf("disconnect not recorded yet")
		}
		return nil
	})
	sess.mu.Lock()
	sess.disconnectedAt = time.Now().Unix() - 500
	sess.mu.Unlock()
	asm.cancelSessionExpiry(idHash)

	// The reconnect must get a fresh session, not the overdue one.
	c2, r2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "odr", props: mqttV5ConnPropsSessionExpiry(120)}, o.MQTT.Host, o.MQTT.Port)
	defer c2.Close()
	sp, reason, _ := testMQTTReadConnAckV5(t, r2)
	if reason != mqttReasonSuccess {
		t.Fatalf("Expected successful CONNACK, got reason 0x%x", reason)
	}
	if sp {
		t.Fatal("Expected session-present=0 for an overdue session")
	}
}

// A session record left with DisconnectedAt=0 by an owner that crashed while
// the client was connected is stamped by the periodic sweep and expired, so a
// finite Session Expiry Interval is eventually honored.
func TestMQTTv5SessionExpiryOwnerCrashSweep(t *testing.T) {
	old := mqttSessionExpirySweepInterval
	mqttSessionExpirySweepInterval = 250 * time.Millisecond
	defer func() { mqttSessionExpirySweepInterval = old }()

	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// First MQTT connect creates the account session manager (and its sweeper).
	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "crashaux", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)

	// Plant an orphaned record: finite expiry, never marked disconnected —
	// what a crash mid-connection leaves behind. The Origin deliberately does
	// not match this process: standalone node names are generated, so after a
	// real restart the crashed owner's name never matches, and the sweep must
	// still reclaim the record.
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	rec, err := json.Marshal(&mqttPersistedSession{ID: "ghost", Origin: "crashed-node", ExpiryInterval: 1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ghostSubj := mqttSessStreamSubjectPrefix + getHash("ghost")
	if _, err := js.Publish(ghostSubj, rec); err != nil {
		t.Fatalf("plant ghost record: %v", err)
	}

	// The periodic sweep stamps the disconnect, arms the 1s deadline, and the
	// expiry deletes the record.
	checkFor(t, 10*time.Second, 100*time.Millisecond, func() error {
		if _, err := js.GetLastMsg(mqttSessStreamName, ghostSubj); err == nil {
			return fmt.Errorf("ghost session record still present")
		}
		return nil
	})
}

// ---- v5 Subscription Identifier ----

// mqttV5SubIDProps builds a SUBSCRIBE properties block carrying a single
// Subscription Identifier.
func mqttV5SubIDProps(id int) []byte {
	body := newMQTTWriter(0)
	body.WriteByte(mqttPropSubscriptionID)
	body.WriteVarInt(id)
	return mqttMakePropsBlock(body.Bytes())
}

// testMQTTCheckSubID asserts the delivered properties carry exactly the given
// Subscription Identifier; id == 0 asserts none.
func testMQTTCheckSubID(t testing.TB, p *mqttProperties, id int) {
	t.Helper()
	var got []int
	if p != nil {
		got = p.subIDs
	}
	if id == 0 {
		if len(got) != 0 {
			t.Fatalf("Expected no subscription identifier, got %v", got)
		}
		return
	}
	if len(got) != 1 || got[0] != id {
		t.Fatalf("Expected subscription identifier [%d], got %v", id, got)
	}
}

// testMQTTReadPubV5Raw reads a delivered v5 PUBLISH, validates topic/payload, and
// returns its first byte (for the DUP/RETAIN flags), packet id, and parsed
// properties without acking (so a QoS1 redelivery can be observed).
func testMQTTReadPubV5Raw(t testing.TB, r *mqttReader, expTopic string, expPayload []byte) (byte, uint16, *mqttProperties) {
	t.Helper()
	b, pl := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketPub {
		t.Fatalf("Expected PUBLISH (%x), got %x", mqttPacketPub, pt)
	}
	start := r.pos
	qos := mqttGetQoS(b & mqttPacketFlagMask)
	topic, err := r.readBytes("topic", false)
	if err != nil {
		t.Fatalf("Error reading topic: %v", err)
	}
	if string(topic) != expTopic {
		t.Fatalf("Expected topic %q, got %q", expTopic, topic)
	}
	var pi uint16
	if qos > 0 {
		if pi, err = r.readUint16("pi"); err != nil {
			t.Fatalf("Error reading pi: %v", err)
		}
	}
	props, err := r.readProperties(mqttPropsContextPubOut)
	if err != nil {
		t.Fatalf("Error reading PUBLISH properties: %v", err)
	}
	payloadLen := pl - (r.pos - start)
	if payloadLen < 0 || r.pos+payloadLen > len(r.buf) {
		t.Fatalf("Invalid payload length %d", payloadLen)
	}
	got := r.buf[r.pos : r.pos+payloadLen]
	r.pos += payloadLen
	if string(got) != string(expPayload) {
		t.Fatalf("Expected payload %q, got %q", expPayload, got)
	}
	return b, pi, props
}

// A Subscription Identifier is injected into every PUBLISH delivered because of
// the subscription that carries it, across QoS0 and QoS1 delivery. Spec5
// [3.8.2.1.2].
func TestMQTTv5SubscriptionIdentifier(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	newPub := func(id string) (net.Conn, *mqttReader) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: id, cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		return c, r
	}

	t.Run("QoS0", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid0", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(42), []mqttV5SubFilter{{topic: "sid0/t", opts: 0}})

		// Control subscriber without an identifier gets none.
		cc, rc := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid0-ctl", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer cc.Close()
		testMQTTReadConnAckV5(t, rc)
		testMQTTSubV5(t, cc, rc, 1, []mqttV5SubFilter{{topic: "sid0/t", opts: 0}})

		p, rp := newPub("sid0-pub")
		defer p.Close()
		testMQTTPubV5Props(t, p, rp, 0, false, 0, "sid0/t", []byte("m"), nil)

		testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, c, r, "sid0/t", []byte("m")), 42)
		testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, cc, rc, "sid0/t", []byte("m")), 0)
	})

	t.Run("QoS1", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid1", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(7), []mqttV5SubFilter{{topic: "sid1/t", opts: 1}})

		p, rp := newPub("sid1-pub")
		defer p.Close()
		testMQTTPubV5Props(t, p, rp, 1, false, 1, "sid1/t", []byte("m"), nil)

		testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, c, r, "sid1/t", []byte("m")), 7)
	})

	// A single SUBSCRIBE identifier applies to every filter in the packet.
	t.Run("applies to all filters", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid-multi", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(15),
			[]mqttV5SubFilter{{topic: "sidm/a", opts: 0}, {topic: "sidm/b", opts: 0}})

		p, rp := newPub("sid-multi-pub")
		defer p.Close()
		testMQTTPubV5Props(t, p, rp, 0, false, 0, "sidm/a", []byte("a"), nil)
		testMQTTPubV5Props(t, p, rp, 0, false, 0, "sidm/b", []byte("b"), nil)

		testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, c, r, "sidm/a", []byte("a")), 15)
		testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, c, r, "sidm/b", []byte("b")), 15)
	})

	// The identifier coexists with properties forwarded from the publisher.
	t.Run("with forwarded props", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid-fwd", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(11), []mqttV5SubFilter{{topic: "sidf/t", opts: 1}})

		p, rp := newPub("sid-fwd-pub")
		defer p.Close()
		testMQTTPubV5Props(t, p, rp, 1, false, 1, "sidf/t", []byte("m"), testMQTTv5PubPropsBlock())

		props := testMQTTReadPubV5Props(t, c, r, "sidf/t", []byte("m"))
		testMQTTCheckFwdProps(t, props)
		testMQTTCheckSubID(t, props, 11)
	})

	// A '#' subscription delivers at the parent level through a companion sub; the
	// identifier must reach both.
	t.Run("level-up companion sub", func(t *testing.T) {
		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid-lvl", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(33), []mqttV5SubFilter{{topic: "lvl/#", opts: 0}})

		p, rp := newPub("sid-lvl-pub")
		defer p.Close()
		testMQTTPubV5Props(t, p, rp, 0, false, 0, "lvl", []byte("parent"), nil)
		testMQTTPubV5Props(t, p, rp, 0, false, 0, "lvl/child", []byte("child"), nil)

		testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, c, r, "lvl", []byte("parent")), 33)
		testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, c, r, "lvl/child", []byte("child")), 33)
	})
}

// A retained message replayed to a new subscription carries the subscription's
// identifier, and the Message Expiry rewrite composes with the injection. Spec5
// [3.8.2.1.2], [3.3.2.3.3].
func TestMQTTv5SubscriptionIdentifierRetained(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	t.Run("plain", func(t *testing.T) {
		p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sidret-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer p.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, p, rp, 1, true, 1, "sidret/t", []byte("ret"), nil)

		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sidret-sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(9), []mqttV5SubFilter{{topic: "sidret/t", opts: 1}})

		b, _, props := testMQTTReadPubV5Raw(t, r, "sidret/t", []byte("ret"))
		if b&mqttPubFlagRetain == 0 {
			t.Fatal("retained replay must set RETAIN")
		}
		testMQTTCheckSubID(t, props, 9)
	})

	// The identifier injection composes with the Message Expiry rewrite the
	// retained path applies (the two touch the same properties block).
	t.Run("with message expiry", func(t *testing.T) {
		expBody := newMQTTWriter(0)
		expBody.WriteByte(mqttPropMessageExpiry)
		expBody.WriteUint32(3600)
		p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sidrete-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer p.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, p, rp, 1, true, 1, "sidrete/t", []byte("ret"), mqttMakePropsBlock(expBody.Bytes()))

		c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sidrete-sub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer c.Close()
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(19), []mqttV5SubFilter{{topic: "sidrete/t", opts: 1}})

		_, _, props := testMQTTReadPubV5Raw(t, r, "sidrete/t", []byte("ret"))
		testMQTTCheckSubID(t, props, 19)
		if !props.present[mqttPropMessageExpiry] || props.messageExpiry == 0 || props.messageExpiry > 3600 {
			t.Fatalf("expected a reduced non-zero message expiry, got present=%v val=%d",
				props.present[mqttPropMessageExpiry], props.messageExpiry)
		}
	})
}

// Overlapping subscriptions are not coalesced: a topic matching two filters, each
// with its own identifier, yields one PUBLISH per subscription carrying that
// subscription's identifier. Spec5 [3.8.2.1.2].
func TestMQTTv5SubscriptionIdentifierOverlapping(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid-ov", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)
	testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(5), []mqttV5SubFilter{{topic: "ov/+", opts: 0}})
	testMQTTSubV5Props(t, c, r, 2, mqttV5SubIDProps(9), []mqttV5SubFilter{{topic: "ov/topic", opts: 0}})

	p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid-ov-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer p.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, p, rp, 0, false, 0, "ov/topic", []byte("m"), nil)

	// Two PUBLISHes arrive (one per matching subscription); order is not defined.
	seen := map[int]bool{}
	for i := 0; i < 2; i++ {
		_, _, props := testMQTTReadPubV5Raw(t, r, "ov/topic", []byte("m"))
		if props == nil || len(props.subIDs) != 1 {
			t.Fatalf("Expected exactly one subscription identifier per delivery, got %v", props)
		}
		seen[props.subIDs[0]] = true
	}
	if !seen[5] || !seen[9] {
		t.Fatalf("Expected deliveries carrying identifiers 5 and 9, got %v", seen)
	}
}

// A re-SUBSCRIBE to the same filter replaces its identifier; re-subscribing with
// no identifier clears it. Spec5 [3.8.2.1.2], [MQTT-3.8.4-3].
func TestMQTTv5ResubscribeReplacesSubscriptionID(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid-re", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	testMQTTReadConnAckV5(t, r)

	p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid-re-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer p.Close()
	testMQTTReadConnAckV5(t, rp)

	pubAndCheck := func(pi uint16, props []byte, expID int) {
		testMQTTSubV5Props(t, c, r, pi, props, []mqttV5SubFilter{{topic: "sidre/t", opts: 0}})
		testMQTTPubV5Props(t, p, rp, 0, false, 0, "sidre/t", []byte("m"), nil)
		testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, c, r, "sidre/t", []byte("m")), expID)
	}

	pubAndCheck(1, mqttV5SubIDProps(1), 1) // initial identifier
	pubAndCheck(2, mqttV5SubIDProps(2), 2) // replaced
	pubAndCheck(3, nil, 0)                 // re-subscribe with no identifier clears it
}

// A Subscription Identifier survives a persistent session's reconnect, for both a
// fresh publish and the redelivery of an unacked QoS1 message. Spec5 [3.8.2.1.2].
func TestMQTTv5SubscriptionIdentifierRestoredOnReconnect(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	t.Run("fresh publish after reconnect", func(t *testing.T) {
		ci := &mqttV5ConnInfo{clientID: "sid-persist", props: mqttV5ConnPropsSessionExpiry(30)}
		c, r := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(77), []mqttV5SubFilter{{topic: "sidp/t", opts: 1}})
		if _, err := testMQTTWrite(c, []byte{mqttPacketDisconnect, 0}); err != nil {
			t.Fatalf("Error writing DISCONNECT: %v", err)
		}
		c.Close()

		c2, r2 := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); !sp {
			t.Fatal("Expected session present on reconnect")
		}

		p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sidp-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer p.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, p, rp, 1, false, 1, "sidp/t", []byte("after"), nil)
		testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, c2, r2, "sidp/t", []byte("after")), 77)
	})

	t.Run("pending redelivery keeps id", func(t *testing.T) {
		ci := &mqttV5ConnInfo{clientID: "sid-pr", props: mqttV5ConnPropsSessionExpiry(30)}
		c, r := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
		testMQTTReadConnAckV5(t, r)
		testMQTTSubV5Props(t, c, r, 1, mqttV5SubIDProps(21), []mqttV5SubFilter{{topic: "sidpr/t", opts: 1}})

		p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sidpr-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
		defer p.Close()
		testMQTTReadConnAckV5(t, rp)
		testMQTTPubV5Props(t, p, rp, 1, false, 1, "sidpr/t", []byte("m"), nil)

		// Receive but do NOT ack.
		b, _, props := testMQTTReadPubV5Raw(t, r, "sidpr/t", []byte("m"))
		if b&mqttPubFlagDup != 0 {
			t.Fatal("first delivery should not be DUP")
		}
		testMQTTCheckSubID(t, props, 21)
		c.Close()

		// Reconnect: the unacked QoS1 message is redelivered with DUP set and the
		// identifier restored from the persisted session.
		c2, r2 := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
		defer c2.Close()
		if sp, _, _ := testMQTTReadConnAckV5(t, r2); !sp {
			t.Fatal("Expected session present on reconnect")
		}
		b2, pi2, props2 := testMQTTReadPubV5Raw(t, r2, "sidpr/t", []byte("m"))
		if b2&mqttPubFlagDup == 0 {
			t.Fatal("redelivery should be DUP")
		}
		testMQTTCheckSubID(t, props2, 21)
		pa := [4]byte{mqttPacketPubAck, 0x2, byte(pi2 >> 8), byte(pi2)}
		if _, err := testMQTTWrite(c2, pa[:]); err != nil {
			t.Fatalf("Error writing PUBACK: %v", err)
		}
	})
}

// A v5 subscriber with a Subscription Identifier and a 3.1.1 subscriber on the
// same topic: only the v5 delivery carries the identifier; the 3.1.1 delivery has
// no properties section at all.
func TestMQTTv5SubscriptionIdentifier311Unaffected(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c5, r5 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid-v5", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c5.Close()
	testMQTTReadConnAckV5(t, r5)
	testMQTTSubV5Props(t, c5, r5, 1, mqttV5SubIDProps(8), []mqttV5SubFilter{{topic: "mix/t", opts: 0}})

	c3, r3 := testMQTTConnect(t, &mqttConnInfo{clientID: "sid-311", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer c3.Close()
	testMQTTCheckConnAck(t, r3, mqttConnAckRCConnectionAccepted, false)
	testMQTTSub(t, 1, c3, r3, []*mqttFilter{{filter: "mix/t", qos: 0}}, []byte{0})

	p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "mix-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer p.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, p, rp, 0, false, 0, "mix/t", []byte("m"), nil)

	testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, c5, r5, "mix/t", []byte("m")), 8)
	// The 3.1.1 subscriber gets a plain PUBLISH (no properties section on the wire).
	testMQTTCheckPubMsg(t, c3, r3, "mix/t", 0, []byte("m"))
}

// A SUBSCRIBE carrying more than one Subscription Identifier, or one with value 0,
// is a Protocol Error. Spec5 [MQTT-3.8.2.1.2], [3.3.2.3.8].
func TestMQTTv5SubscribeSubscriptionIDProtocolErrors(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	twoIDs := func() []byte {
		body := newMQTTWriter(0)
		body.WriteByte(mqttPropSubscriptionID)
		body.WriteVarInt(1)
		body.WriteByte(mqttPropSubscriptionID)
		body.WriteVarInt(2)
		return mqttMakePropsBlock(body.Bytes())
	}()

	for _, test := range []struct {
		name  string
		props []byte
	}{
		{"more than one identifier", twoIDs},
		{"identifier of zero", mqttV5SubIDProps(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sid-err", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer c.Close()
			testMQTTReadConnAckV5(t, r)

			vh := newMQTTWriter(0)
			vh.WriteUint16(1)
			vh.Write(test.props)
			vh.WriteBytes([]byte("foo"))
			vh.WriteByte(0x00)
			w := newMQTTWriter(0)
			w.WriteByte(mqttPacketSub | mqttSubscribeFlags)
			w.WriteVarInt(vh.Len())
			w.Write(vh.Bytes())
			if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
				t.Fatalf("Error writing SUBSCRIBE: %v", err)
			}

			b, _ := testMQTTReadPacket(t, r)
			if pt := b & mqttPacketMask; pt != mqttPacketDisconnect {
				t.Fatalf("Expected DISCONNECT (%x), got %x", mqttPacketDisconnect, pt)
			}
			reason, err := r.readByte("disconnect reason")
			if err != nil {
				t.Fatalf("Error reading disconnect reason: %v", err)
			}
			if reason != mqttReasonProtocolError {
				t.Fatalf("Expected protocol error 0x%x, got 0x%x", mqttReasonProtocolError, reason)
			}
		})
	}
}

// A message that fits a client's Maximum Packet Size without the injected
// Subscription Identifier but exceeds it once injected must be discarded; the
// injection therefore has to happen before the size check. Spec5 [3.1.2.11.4].
func TestMQTTv5SubscriptionIdentifierMaxPacketSize(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	maxPktProps := func(sz uint32) []byte {
		body := newMQTTWriter(0)
		body.WriteByte(mqttPropMaxPacketSize)
		body.WriteUint32(sz)
		return body.Bytes()
	}

	topic := "sidmps/t"
	payload := []byte(strings.Repeat("x", 20))
	// QoS0 packet size WITHOUT an injected identifier: fixed header (1) + remaining
	// length varint (1, since rem < 128) + topic (2 + len) + empty props (1) +
	// payload. Injecting a small identifier adds 2 bytes, pushing it over.
	rem := 2 + len(topic) + 1 + len(payload)
	pktNoSubID := uint32(1 + 1 + rem)

	// Subscriber A: identifier + a Maximum Packet Size that exactly fits the
	// un-injected PUBLISH. The injected identifier must push it over the limit.
	ca, ra := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sidmps-a", cleanStart: true, props: maxPktProps(pktNoSubID)}, o.MQTT.Host, o.MQTT.Port)
	defer ca.Close()
	testMQTTReadConnAckV5(t, ra)
	testMQTTSubV5Props(t, ca, ra, 1, mqttV5SubIDProps(3), []mqttV5SubFilter{{topic: topic, opts: 0}})

	// Subscriber B: same limit but no identifier; the PUBLISH fits and is delivered.
	cb, rb := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sidmps-b", cleanStart: true, props: maxPktProps(pktNoSubID)}, o.MQTT.Host, o.MQTT.Port)
	defer cb.Close()
	testMQTTReadConnAckV5(t, rb)
	testMQTTSubV5(t, cb, rb, 1, []mqttV5SubFilter{{topic: topic, opts: 0}})

	p, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "sidmps-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer p.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, p, rp, 0, false, 0, topic, payload, nil)

	// B fits without injection and receives it.
	testMQTTReadPubV5Props(t, cb, rb, topic, payload)

	// A must NOT receive it (injection pushes it over the limit). Prove A is alive
	// and the message was dropped, not delayed, by sending a small follow-up that
	// fits even with the identifier: A's next PUBLISH is that follow-up.
	testMQTTPubV5Props(t, p, rp, 0, false, 0, topic, []byte("s"), nil)
	testMQTTCheckSubID(t, testMQTTReadPubV5Props(t, ca, ra, topic, []byte("s")), 3)
}

// Unit test of mqttInjectSubID: the property is appended to (or synthesized as) a
// well-formed block, and out-of-range ids or unsafe/malformed blocks are left
// unchanged. Spec5 [3.8.2.1.2].
func TestMQTTv5InjectSubID(t *testing.T) {
	parse := func(block []byte) *mqttProperties {
		t.Helper()
		r := &mqttReader{}
		r.reset(block)
		p, err := r.readProperties(mqttPropsContextPubOut)
		if err != nil || r.hasMore() {
			t.Fatalf("re-parse injected block: err=%v hasMore=%v", err, r.hasMore())
		}
		return p
	}
	checkOnly := func(block []byte, id int) {
		t.Helper()
		p := parse(block)
		if len(p.subIDs) != 1 || p.subIDs[0] != id {
			t.Fatalf("Expected subscription identifier [%d], got %v", id, p.subIDs)
		}
	}

	// Synthesize a fresh block from nil and from an empty (single 0) block.
	checkOnly(mqttInjectSubID(nil, 5), 5)
	checkOnly(mqttInjectSubID([]byte{0}, 6), 6)
	// Maximum valid identifier (multi-byte varint).
	checkOnly(mqttInjectSubID(nil, mqttMaxVarInt), mqttMaxVarInt)

	// Append to an existing forwardable block: all original props plus the id.
	valid := testMQTTv5PubPropsBlock()
	out := mqttInjectSubID(valid, 7)
	p := parse(out)
	testMQTTCheckFwdProps(t, p)
	if len(p.subIDs) != 1 || p.subIDs[0] != 7 {
		t.Fatalf("Expected subscription identifier [7], got %v", p.subIDs)
	}

	// Unchanged cases: out-of-range id, an unsafe block (Topic Alias), and a block
	// with a valid length prefix but an invalid body.
	topicAlias := mqttMakePropsBlock([]byte{mqttPropTopicAlias, 0x00, 0x01})
	badBody := []byte{0x02, 0x99, 0x99} // length 2, body is not a valid property
	for _, test := range []struct {
		name string
		in   []byte
		id   int
	}{
		{"id zero", valid, 0},
		{"id negative", valid, -1},
		{"id too large", valid, mqttMaxVarInt + 1},
		{"topic alias unsafe", topicAlias, 5},
		{"invalid body", badBody, 5},
	} {
		if got := mqttInjectSubID(test.in, test.id); !bytes.Equal(got, test.in) {
			t.Fatalf("%s: expected props unchanged, got %v (in %v)", test.name, got, test.in)
		}
	}
}

// ---- Topic Alias (Spec5 [3.3.2.3.4]) ----

// mqttTopicAliasProp is the Topic Alias property bytes (id + 2-byte value).
func mqttTopicAliasProp(alias uint16) []byte {
	return []byte{mqttPropTopicAlias, byte(alias >> 8), byte(alias)}
}

// testMQTTSendPubV5Raw writes a v5 PUBLISH with the given raw properties block
// (which must include its length prefix) and does NOT read any acknowledgement.
// Suitable for QoS 0 publishes and for error cases that expect a DISCONNECT.
func testMQTTSendPubV5Raw(t testing.TB, c net.Conn, qos byte, pi uint16, retain bool, topic string, props, payload []byte) {
	t.Helper()
	flags := qos << 1
	if retain {
		flags |= mqttPubFlagRetain
	}
	vh := newMQTTWriter(0)
	vh.WriteBytes([]byte(topic))
	if qos > 0 {
		vh.WriteUint16(pi)
	}
	if len(props) > 0 {
		vh.Write(props)
	} else {
		vh.WriteVarInt(0)
	}
	vh.Write(payload)
	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketPub | flags)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())
	if _, err := testMQTTWrite(c, w.Bytes()); err != nil {
		t.Fatalf("Error writing PUBLISH: %v", err)
	}
}

// testMQTTReadDisconnectReason reads a v5 DISCONNECT and returns its reason code.
func testMQTTReadDisconnectReason(t testing.TB, r *mqttReader) byte {
	t.Helper()
	b, _ := testMQTTReadPacket(t, r)
	if pt := b & mqttPacketMask; pt != mqttPacketDisconnect {
		t.Fatalf("Expected DISCONNECT (%x), got %x", mqttPacketDisconnect, pt)
	}
	reason, err := r.readByte("disconnect reason")
	if err != nil {
		t.Fatalf("Error reading disconnect reason: %v", err)
	}
	return reason
}

// The advertised Topic Alias Maximum in the CONNACK reflects the configured
// option: default when unset, the explicit value otherwise, and omitted (absent
// => 0) when disabled.
func TestMQTTv5TopicAliasMaxAdvertised(t *testing.T) {
	for _, test := range []struct {
		name   string
		opt    int
		expSet bool
		expVal uint16
	}{
		{"default", 0, true, mqttDefaultTopicAliasMax},
		{"explicit", 5, true, 5},
		{"disabled", -1, false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := testMQTTDefaultOptionsV5()
			o.MQTT.TopicAliasMaximum = test.opt
			s := testMQTTRunServer(t, o)
			defer testMQTTShutdownServer(s)

			c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "tam", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer c.Close()
			_, reason, props := testMQTTReadConnAckV5(t, r)
			if reason != mqttReasonSuccess {
				t.Fatalf("Expected success, got 0x%x", reason)
			}
			if props.present[mqttPropTopicAliasMax] != test.expSet {
				t.Fatalf("Topic Alias Maximum present=%v, want %v", props.present[mqttPropTopicAliasMax], test.expSet)
			}
			if test.expSet && props.topicAliasMax != test.expVal {
				t.Fatalf("Topic Alias Maximum=%d, want %d", props.topicAliasMax, test.expVal)
			}
		})
	}
}

// The server advertises Server Keep Alive only when it overrides the client's
// requested keep alive: never when the option is unset, and only when the
// client asked for 0 (none) or a value above the configured maximum.
func TestMQTTv5ServerKeepAliveAdvertised(t *testing.T) {
	for _, test := range []struct {
		name     string
		opt      int
		clientKA uint16
		expSet   bool
		expVal   uint16
	}{
		{"unset with none", 0, 0, false, 0},
		{"unset with value", 0, 30, false, 0},
		{"override none", 10, 0, true, 10},
		{"override above max", 10, 60, true, 10},
		{"at max", 10, 10, false, 0},
		{"below max", 10, 5, false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := testMQTTDefaultOptionsV5()
			o.MQTT.KeepAliveMaximum = test.opt
			s := testMQTTRunServer(t, o)
			defer testMQTTShutdownServer(s)

			ci := &mqttV5ConnInfo{clientID: "ska", cleanStart: true, keepAlive: test.clientKA}
			c, r := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
			defer c.Close()
			_, reason, props := testMQTTReadConnAckV5(t, r)
			if reason != mqttReasonSuccess {
				t.Fatalf("Expected success, got 0x%x", reason)
			}
			if props.present[mqttPropServerKeepAlive] != test.expSet {
				t.Fatalf("Server Keep Alive present=%v, want %v", props.present[mqttPropServerKeepAlive], test.expSet)
			}
			if test.expSet && props.serverKeepAlive != test.expVal {
				t.Fatalf("Server Keep Alive=%d, want %d", props.serverKeepAlive, test.expVal)
			}
		})
	}
}

// With keep_alive_maximum set, a v5 client that requested no keep alive is still
// disconnected once the enforced deadline (1.5x the maximum) elapses, while a
// 3.1.1 client on the same server keeps its (absent) keep alive: the override is
// silently inapplicable to v4, which has no way to be told of it.
func TestMQTTv5ServerKeepAliveEnforced(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	o.MQTT.KeepAliveMaximum = 1
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// v5 client requesting no keep alive: server enforces 1s => 1.5s deadline.
	c5, r5 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "v5ka", cleanStart: true, keepAlive: 0}, o.MQTT.Host, o.MQTT.Port)
	defer c5.Close()
	if _, reason, _ := testMQTTReadConnAckV5(t, r5); reason != mqttReasonSuccess {
		t.Fatalf("Expected success, got 0x%x", reason)
	}

	// 3.1.1 control also requesting no keep alive: no override, stays connected.
	c4, r4 := testMQTTConnect(t, &mqttConnInfo{cleanSess: true, keepAlive: 0}, o.MQTT.Host, o.MQTT.Port)
	defer c4.Close()
	testMQTTCheckConnAck(t, r4, mqttConnAckRCConnectionAccepted, false)

	time.Sleep(2 * time.Second)
	testMQTTExpectDisconnect(t, c5)
	// The v4 client is still alive: a PING round-trips.
	testMQTTFlush(t, c4, nil, r4)
}

// A client binds a Topic Alias with a full-topic PUBLISH, then publishes with an
// empty topic + the alias; the server resolves it and delivers on the bound
// topic. Exercised at QoS 0 and QoS 1.
func TestMQTTv5TopicAliasPublish(t *testing.T) {
	for _, qos := range []byte{0, 1} {
		t.Run(fmt.Sprintf("qos%d", qos), func(t *testing.T) {
			o := testMQTTDefaultOptionsV5()
			s := testMQTTRunServer(t, o)
			defer testMQTTShutdownServer(s)

			topic := fmt.Sprintf("ta/q%d", qos)
			cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "tasub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer cs.Close()
			testMQTTReadConnAckV5(t, rs)
			testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: topic, opts: 1}})
			testMQTTFlush(t, cs, nil, rs)

			cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "tapub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer cp.Close()
			testMQTTReadConnAckV5(t, rp)

			// Bind alias 1 -> topic, then publish alias-only with an empty topic.
			alias := mqttMakePropsBlock(mqttTopicAliasProp(1))
			testMQTTPubV5Props(t, cp, rp, qos, false, 1, topic, []byte("first"), alias)
			testMQTTPubV5Props(t, cp, rp, qos, false, 2, "", []byte("second"), alias)

			// Both are delivered on the resolved topic with no alias leaked.
			for _, exp := range []string{"first", "second"} {
				props := testMQTTReadPubV5Props(t, cs, rs, topic, []byte(exp))
				if props != nil && props.present[mqttPropTopicAlias] {
					t.Fatalf("Topic Alias leaked to subscriber for %q", exp)
				}
			}
		})
	}
}

// Invalid Topic Alias values close the connection with the proper reason: 0 or
// above the advertised maximum => 0x94 (Topic Alias invalid); an empty topic
// with an unbound alias => 0x82 (Protocol Error).
func TestMQTTv5TopicAliasErrors(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	o.MQTT.TopicAliasMaximum = 5
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	for _, test := range []struct {
		name   string
		topic  string
		alias  uint16
		reason byte
	}{
		{"alias zero", "foo", 0, mqttReasonTopicAliasInvalid},
		{"alias exceeds max", "foo", 6, mqttReasonTopicAliasInvalid},
		{"unknown alias", "", 3, mqttReasonProtocolError},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "tae", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer c.Close()
			testMQTTReadConnAckV5(t, r)

			props := mqttMakePropsBlock(mqttTopicAliasProp(test.alias))
			testMQTTSendPubV5Raw(t, c, 0, 0, false, test.topic, props, []byte("m"))
			if reason := testMQTTReadDisconnectReason(t, r); reason != test.reason {
				t.Fatalf("Expected reason 0x%x, got 0x%x", test.reason, reason)
			}
		})
	}
}

// Re-binding an existing alias to a new topic overwrites the previous binding;
// a subsequent alias-only PUBLISH follows the new topic. Spec5 [3.3.2.3.4].
func TestMQTTv5TopicAliasRemap(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rmsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "rm/#", opts: 0}})
	testMQTTFlush(t, cs, nil, rs)

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rmpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)

	alias := mqttMakePropsBlock(mqttTopicAliasProp(1))
	testMQTTPubV5Props(t, cp, rp, 0, false, 0, "rm/a", []byte("to-a"), alias)
	testMQTTReadPubV5Props(t, cs, rs, "rm/a", []byte("to-a"))

	// Re-bind alias 1 to rm/b, then publish alias-only.
	testMQTTPubV5Props(t, cp, rp, 0, false, 0, "rm/b", []byte("bind-b"), alias)
	testMQTTReadPubV5Props(t, cs, rs, "rm/b", []byte("bind-b"))
	testMQTTPubV5Props(t, cp, rp, 0, false, 0, "", []byte("to-b"), alias)
	testMQTTReadPubV5Props(t, cs, rs, "rm/b", []byte("to-b"))
}

// The Topic Alias property is stripped before a PUBLISH is forwarded to a
// subscriber: other properties survive, and when the alias was the only property
// the subscriber receives an empty block.
func TestMQTTv5TopicAliasStrippedOnForward(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "stsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "st/#", opts: 1}})
	testMQTTFlush(t, cs, nil, rs)

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "stpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)

	// Alias interleaved with the standard forwardable properties.
	body := newMQTTWriter(0)
	body.Write(mqttTopicAliasProp(7))
	body.WriteByte(mqttPropPayloadFormat)
	body.WriteByte(1)
	body.WriteByte(mqttPropContentType)
	body.WriteString("application/json")
	body.WriteByte(mqttPropResponseTopic)
	body.WriteString("resp/topic")
	body.WriteByte(mqttPropCorrelationData)
	body.WriteBytes([]byte("corr-1"))
	body.WriteByte(mqttPropUserProperty)
	body.WriteString("k1")
	body.WriteString("v1")
	body.WriteByte(mqttPropUserProperty)
	body.WriteString("k2")
	body.WriteString("v2")
	testMQTTPubV5Props(t, cp, rp, 1, false, 1, "st/a", []byte("payload"), mqttMakePropsBlock(body.Bytes()))

	props := testMQTTReadPubV5Props(t, cs, rs, "st/a", []byte("payload"))
	if props != nil && props.present[mqttPropTopicAlias] {
		t.Fatal("Topic Alias leaked to subscriber")
	}
	testMQTTCheckFwdProps(t, props)

	// Alias-only: the subscriber must receive an empty properties block.
	aliasOnly := mqttMakePropsBlock(mqttTopicAliasProp(7))
	testMQTTPubV5Props(t, cp, rp, 1, false, 2, "st/b", []byte("bare"), aliasOnly)
	if props := testMQTTReadPubV5Props(t, cs, rs, "st/b", []byte("bare")); props != nil {
		t.Fatalf("Expected empty properties, got %+v", props)
	}
}

// A retained PUBLISH carrying a Topic Alias stores the message alias-free: a
// late subscriber gets the retained message with the alias stripped, and an
// alias-only retained PUBLISH retains under the resolved topic.
func TestMQTTv5TopicAliasStrippedInRetained(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rtpub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)

	// Bind alias 1 to rt/a with a retained, property-bearing message.
	body := newMQTTWriter(0)
	body.Write(mqttTopicAliasProp(1))
	body.WriteByte(mqttPropContentType)
	body.WriteString("application/json")
	testMQTTPubV5Props(t, cp, rp, 1, true, 1, "rt/a", []byte("kept"), mqttMakePropsBlock(body.Bytes()))

	// Alias-only retained publish retains under the resolved topic rt/b... first
	// bind alias 2 -> rt/b (non-retained), then retain alias-only.
	alias2 := mqttMakePropsBlock(mqttTopicAliasProp(2))
	testMQTTPubV5Props(t, cp, rp, 1, false, 2, "rt/b", []byte("ignore"), alias2)
	testMQTTPubV5Props(t, cp, rp, 1, true, 3, "", []byte("kept-b"), alias2)

	// A late subscriber receives both retained messages, alias-free.
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "rtsub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cs.Close()
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "rt/#", opts: 1}})

	got := map[string]string{}
	for i := 0; i < 2; i++ {
		b, pl := testMQTTReadPacket(t, rs)
		if pt := b & mqttPacketMask; pt != mqttPacketPub {
			t.Fatalf("Expected retained PUBLISH, got %x", pt)
		}
		start := rs.pos
		topic, _ := rs.readBytes("topic", false)
		pi, _ := rs.readUint16("pi")
		props, err := rs.readProperties(mqttPropsContextPubOut)
		if err != nil {
			t.Fatalf("Error reading retained props: %v", err)
		}
		if props != nil && props.present[mqttPropTopicAlias] {
			t.Fatalf("Topic Alias leaked in retained message for %q", topic)
		}
		payload := rs.buf[rs.pos : start+pl]
		got[string(topic)] = string(payload)
		rs.pos = start + pl
		pa := [4]byte{mqttPacketPubAck, 0x2, byte(pi >> 8), byte(pi)}
		testMQTTWrite(cs, pa[:])
	}
	if got["rt/a"] != "kept" || got["rt/b"] != "kept-b" {
		t.Fatalf("Unexpected retained delivery: %+v", got)
	}
}

// When topic aliases are disabled (TopicAliasMaximum -1), the CONNACK omits the
// property and any alias-bearing PUBLISH is rejected with 0x94.
func TestMQTTv5TopicAliasDisabled(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	o.MQTT.TopicAliasMaximum = -1
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "dis", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer c.Close()
	_, _, props := testMQTTReadConnAckV5(t, r)
	if props.present[mqttPropTopicAliasMax] {
		t.Fatal("Topic Alias Maximum must be omitted when disabled")
	}
	testMQTTSendPubV5Raw(t, c, 0, 0, false, "foo", mqttMakePropsBlock(mqttTopicAliasProp(1)), []byte("m"))
	if reason := testMQTTReadDisconnectReason(t, r); reason != mqttReasonTopicAliasInvalid {
		t.Fatalf("Expected 0x%x, got 0x%x", mqttReasonTopicAliasInvalid, reason)
	}
}

// Topic aliases are connection-scoped: after a reconnect (even with the session
// present), a previously bound alias is unknown, so an alias-only PUBLISH is a
// Protocol Error.
func TestMQTTv5TopicAliasConnectionScoped(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	ci := &mqttV5ConnInfo{clientID: "scoped", cleanStart: false}
	c, r := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, r)
	alias := mqttMakePropsBlock(mqttTopicAliasProp(1))
	testMQTTPubV5Props(t, c, r, 1, false, 1, "sc/a", []byte("m"), alias)
	c.Close()

	// Reconnect with the same client ID; the session may be present, but the
	// alias map starts empty.
	c2, r2 := testMQTTConnectV5(t, ci, o.MQTT.Host, o.MQTT.Port)
	defer c2.Close()
	testMQTTReadConnAckV5(t, r2)
	testMQTTSendPubV5Raw(t, c2, 0, 0, false, "", alias, []byte("m"))
	if reason := testMQTTReadDisconnectReason(t, r2); reason != mqttReasonProtocolError {
		t.Fatalf("Expected 0x%x, got 0x%x", mqttReasonProtocolError, reason)
	}
}

// mqttStripTopicAlias removes the Topic Alias property and re-encodes the length
// prefix, including where stripping the 3 alias bytes shrinks the prefix across
// the 127/128-byte varint boundary. Every other property must survive intact.
func TestMQTTv5StripTopicAlias(t *testing.T) {
	// A block with no alias is returned unchanged.
	noAlias := testMQTTv5PubPropsBlock()
	if got := mqttStripTopicAlias(noAlias); &got[0] != &noAlias[0] {
		t.Fatal("Expected the same slice back when there is no alias")
	}
	// A block whose only property is the alias strips to nil.
	if got := mqttStripTopicAlias(mqttMakePropsBlock(mqttTopicAliasProp(1))); got != nil {
		t.Fatalf("Expected nil for an alias-only block, got %v", got)
	}

	// padUserProp appends a User Property "p"/value of valueLen bytes; its total
	// wire size is id(1) + 2 + len("p") + 2 + valueLen = 6 + valueLen bytes.
	padUserProp := func(w *mqttWriter, valueLen int) {
		w.WriteByte(mqttPropUserProperty)
		w.WriteString("p")
		w.WriteString(strings.Repeat("x", valueLen))
	}

	// Build blocks where the alias sits first/middle/last, and where the stripped
	// body length lands on 127/128/129 so the varint prefix must re-encode from 2
	// bytes to 1 at the boundary. In the middle case a 2-byte Payload Format
	// property precedes the alias.
	for _, pos := range []string{"first", "middle", "last"} {
		for _, strippedBodyLen := range []int{127, 128, 129, 200} {
			t.Run(fmt.Sprintf("%s-len%d", pos, strippedBodyLen), func(t *testing.T) {
				// Surviving body is the pad User Property (6+valueLen) plus, for the
				// middle case, a 2-byte Payload Format property. Solve for valueLen.
				valueLen := strippedBodyLen - 6
				if pos == "middle" {
					valueLen -= 2
				}
				if valueLen < 0 {
					t.Skipf("cannot build a body of %d bytes", strippedBodyLen)
				}
				body := newMQTTWriter(0)
				switch pos {
				case "first":
					body.Write(mqttTopicAliasProp(9))
					padUserProp(body, valueLen)
				case "middle":
					body.WriteByte(mqttPropPayloadFormat)
					body.WriteByte(1)
					body.Write(mqttTopicAliasProp(9))
					padUserProp(body, valueLen)
				case "last":
					padUserProp(body, valueLen)
					body.Write(mqttTopicAliasProp(9))
				}
				block := mqttMakePropsBlock(body.Bytes())
				out := mqttStripTopicAlias(block)
				if out == nil {
					t.Fatal("Expected a non-nil stripped block")
				}
				// The stripped block must re-parse cleanly with no alias and the
				// User Property intact.
				r := &mqttReader{}
				r.reset(out)
				p, err := r.readProperties(mqttPacketPub)
				if err != nil || r.hasMore() {
					t.Fatalf("re-parse stripped block: err=%v hasMore=%v", err, r.hasMore())
				}
				if p != nil && p.present[mqttPropTopicAlias] {
					t.Fatal("alias survived stripping")
				}
				if len(p.user) != 1 || p.user[0].key != "p" || p.user[0].value != strings.Repeat("x", valueLen) {
					t.Fatalf("user property not preserved: %+v", p.user)
				}
				if pos == "middle" && (!p.present[mqttPropPayloadFormat] || p.payloadFormat != 1) {
					t.Fatal("payload format lost")
				}
			})
		}
	}
}
