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
	vh := newMQTTWriter(0)
	vh.WriteUint16(pi)
	vh.WriteVarInt(0) // empty properties
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
	if _, err := r.readProperties(mqttPacketPub); err != nil {
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
	// Features not implemented by the foundation must be advertised as off
	// (their default is "available", so they must be sent explicitly as 0).
	if !props.present[mqttPropSharedSubAvailable] || props.sharedSubAvail != 0 {
		t.Fatalf("Expected Shared Subscription Available=0")
	}
	if !props.present[mqttPropSubIDAvailable] || props.subIDAvail != 0 {
		t.Fatalf("Expected Subscription Identifier Available=0")
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

// The foundation honors only the QoS bits of the v5 subscription options byte.
// It must reject (not silently ACK) a SUBSCRIBE that sets No Local, Retain As
// Published or a non-zero Retain Handling, rather than acknowledging an option
// it would then ignore (e.g. still replaying retained messages for RH=2).
func TestMQTTv5RejectsUnsupportedSubOptions(t *testing.T) {
	o := testMQTTDefaultOptionsV5()
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	for _, test := range []struct {
		name string
		opts byte
	}{
		{"no local", 0x04},
		{"retain as published", 0x08},
		{"retain handling 1", 0x10},
		{"retain handling 2", 0x20},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, r := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "subopt", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
			defer c.Close()
			testMQTTReadConnAckV5(t, r)

			// Craft a v5 SUBSCRIBE with QoS 1 plus the unsupported option bit.
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

			// The server must NOT send a SUBACK; it closes the connection
			// (optionally preceded by a v5 DISCONNECT).
			buf, err := testMQTTRead(c)
			if err != nil {
				return // connection closed, as expected
			}
			if pt := buf[0] & mqttPacketMask; pt == mqttPacketSubAck {
				t.Fatalf("server acknowledged an unsupported subscription option (got SUBACK)")
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
	props, err := r.readProperties(mqttPacketPub)
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
	if _, err = r.readProperties(mqttPacketPub); err != nil {
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

	off := mqttMessageExpiryOffset(block)
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
	if mqttMessageExpiryOffset(noexp) != -1 {
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

	// A persistent session subscribes, then goes offline.
	cs, rs := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "qexp-sub", cleanStart: false}, o.MQTT.Host, o.MQTT.Port)
	testMQTTReadConnAckV5(t, rs)
	testMQTTSubV5(t, cs, rs, 1, []mqttV5SubFilter{{topic: "qexp/topic", opts: 1}})
	cs.Close()

	cp, rp := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "qexp-pub", cleanStart: true}, o.MQTT.Host, o.MQTT.Port)
	defer cp.Close()
	testMQTTReadConnAckV5(t, rp)
	testMQTTPubV5Props(t, cp, rp, 1, false, 30, "qexp/topic", []byte("gone"), mqttV5PropsWithExpiry(1))

	time.Sleep(2200 * time.Millisecond)

	// Reconnect the persistent session: the expired message must not arrive.
	cs2, rs2 := testMQTTConnectV5(t, &mqttV5ConnInfo{clientID: "qexp-sub", cleanStart: false}, o.MQTT.Host, o.MQTT.Port)
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
	delivery := mqttComputeNatsMsgSize(pp, false, mqttMessageExpiryTTL(props)) // QoS0/1 store form, QoS2 delivery form
	hold := mqttComputeNatsMsgSize(pp, true, 0)                                // QoS2 dedup-hold form

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
