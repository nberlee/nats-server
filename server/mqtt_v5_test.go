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
	"fmt"
	"net"
	"testing"
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
