// Copyright 2020-2026 The NATS Authors
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

package server

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/gsl"
	"github.com/nats-io/nats-server/v2/server/stree"
	"github.com/nats-io/nuid"
)

// References to "spec" here is from https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.pdf

const (
	mqttPacketConnect    = byte(0x10)
	mqttPacketConnectAck = byte(0x20)
	mqttPacketPub        = byte(0x30)
	mqttPacketPubAck     = byte(0x40)
	mqttPacketPubRec     = byte(0x50)
	mqttPacketPubRel     = byte(0x60)
	mqttPacketPubComp    = byte(0x70)
	mqttPacketSub        = byte(0x80)
	mqttPacketSubAck     = byte(0x90)
	mqttPacketUnsub      = byte(0xa0)
	mqttPacketUnsubAck   = byte(0xb0)
	mqttPacketPing       = byte(0xc0)
	mqttPacketPingResp   = byte(0xd0)
	mqttPacketDisconnect = byte(0xe0)
	mqttPacketAuth       = byte(0xf0) // MQTT 5.0 only
	mqttPacketMask       = byte(0xf0)
	mqttPacketFlagMask   = byte(0x0f)

	// Protocol levels. 0x4 is MQTT 3.1.1, 0x5 is MQTT 5.0.
	mqttProtoLevel  = byte(0x4)
	mqttProtoLevel5 = byte(0x5)

	// Connect flags
	mqttConnFlagReserved     = byte(0x1)
	mqttConnFlagCleanSession = byte(0x2)
	mqttConnFlagWillFlag     = byte(0x04)
	mqttConnFlagWillQoS      = byte(0x18)
	mqttConnFlagWillRetain   = byte(0x20)
	mqttConnFlagPasswordFlag = byte(0x40)
	mqttConnFlagUsernameFlag = byte(0x80)

	// Publish flags
	mqttPubFlagRetain = byte(0x01)
	mqttPubFlagQoS    = byte(0x06)
	mqttPubFlagDup    = byte(0x08)
	mqttPubQos1       = byte(0x1 << 1)
	mqttPubQoS2       = byte(0x2 << 1)

	// Subscribe flags
	mqttSubscribeFlags = byte(0x2)
	mqttSubAckFailure  = byte(0x80)

	// Unsubscribe flags
	mqttUnsubscribeFlags = byte(0x2)

	// ConnAck returned codes (MQTT 3.1.1)
	mqttConnAckRCConnectionAccepted          = byte(0x0)
	mqttConnAckRCUnacceptableProtocolVersion = byte(0x1)
	mqttConnAckRCIdentifierRejected          = byte(0x2)
	mqttConnAckRCServerUnavailable           = byte(0x3)
	mqttConnAckRCBadUserOrPassword           = byte(0x4)
	mqttConnAckRCNotAuthorized               = byte(0x5)
	mqttConnAckRCQoS2WillRejected            = byte(0x10)

	// MQTT 5.0 reason codes. The success range (< 0x80) is context dependent
	// (Success, Normal disconnection, Granted QoS 0, ...). Codes >= 0x80 are
	// failures. Only the subset used by this implementation is defined here.
	// Spec [MQTT-2.4].
	mqttReasonSuccess                     = byte(0x00) // also Normal disconnection / Granted QoS 0
	mqttReasonGrantedQoS1                 = byte(0x01)
	mqttReasonGrantedQoS2                 = byte(0x02)
	mqttReasonDisconnectWithWill          = byte(0x04)
	mqttReasonNoMatchingSubscribers       = byte(0x10)
	mqttReasonNoSubscriptionExisted       = byte(0x11)
	mqttReasonUnspecifiedError            = byte(0x80)
	mqttReasonMalformedPacket             = byte(0x81)
	mqttReasonProtocolError               = byte(0x82)
	mqttReasonImplementationSpecificError = byte(0x83)
	mqttReasonUnsupportedProtocolVersion  = byte(0x84)
	mqttReasonClientIDNotValid            = byte(0x85)
	mqttReasonBadUserOrPassword           = byte(0x86)
	mqttReasonNotAuthorized               = byte(0x87)
	mqttReasonServerUnavailable           = byte(0x88)
	mqttReasonServerBusy                  = byte(0x89)
	mqttReasonBadAuthMethod               = byte(0x8c)
	mqttReasonSessionTakenOver            = byte(0x8e)
	mqttReasonTopicNameInvalid            = byte(0x90)
	mqttReasonTopicFilterInvalid          = byte(0x8f)
	mqttReasonPacketIDInUse               = byte(0x91)
	mqttReasonPacketIDNotFound            = byte(0x92)
	mqttReasonQoSNotSupported             = byte(0x9b)
	mqttReasonSharedSubNotSupported       = byte(0x9e)
	mqttReasonSubIDNotSupported           = byte(0xa1)
	mqttReasonWildcardSubNotSupported     = byte(0xa2)

	// MQTT 5.0 property identifiers. Spec [MQTT-2.2.2.2].
	mqttPropPayloadFormat        = byte(0x01) // byte
	mqttPropMessageExpiry        = byte(0x02) // 4-byte int
	mqttPropContentType          = byte(0x03) // UTF-8 string
	mqttPropResponseTopic        = byte(0x08) // UTF-8 string
	mqttPropCorrelationData      = byte(0x09) // binary
	mqttPropSubscriptionID       = byte(0x0b) // variable int (repeatable)
	mqttPropSessionExpiry        = byte(0x11) // 4-byte int
	mqttPropAssignedClientID     = byte(0x12) // UTF-8 string
	mqttPropServerKeepAlive      = byte(0x13) // 2-byte int
	mqttPropAuthMethod           = byte(0x15) // UTF-8 string
	mqttPropAuthData             = byte(0x16) // binary
	mqttPropRequestProblemInfo   = byte(0x17) // byte
	mqttPropWillDelay            = byte(0x18) // 4-byte int
	mqttPropRequestResponseInfo  = byte(0x19) // byte
	mqttPropResponseInfo         = byte(0x1a) // UTF-8 string
	mqttPropServerReference      = byte(0x1c) // UTF-8 string
	mqttPropReasonString         = byte(0x1f) // UTF-8 string
	mqttPropReceiveMaximum       = byte(0x21) // 2-byte int
	mqttPropTopicAliasMax        = byte(0x22) // 2-byte int
	mqttPropTopicAlias           = byte(0x23) // 2-byte int
	mqttPropMaxQoS               = byte(0x24) // byte
	mqttPropRetainAvailable      = byte(0x25) // byte
	mqttPropUserProperty         = byte(0x26) // UTF-8 string pair (repeatable)
	mqttPropMaxPacketSize        = byte(0x27) // 4-byte int
	mqttPropWildcardSubAvailable = byte(0x28) // byte
	mqttPropSubIDAvailable       = byte(0x29) // byte
	mqttPropSharedSubAvailable   = byte(0x2a) // byte

	// Maximum payload size of a control packet
	mqttMaxPayloadSize = 0xFFFFFFF

	// Topic/Filter characters
	mqttTopicLevelSep = '/'
	mqttSingleLevelWC = '+'
	mqttMultiLevelWC  = '#'
	mqttReservedPre   = '$'

	// This is appended to the sid of a subscription that is
	// created on the upper level subject because of the MQTT
	// wildcard '#' semantic.
	mqttMultiLevelSidSuffix = " fwc"

	// This is the prefix used for all subjects used by MQTT code.
	mqttPrefix = "$MQTT."

	// This is the prefix for NATS subscriptions subjects associated as delivery
	// subject of JS consumer. We want to make them unique so will prevent users
	// MQTT subscriptions to start with this.
	mqttSubPrefix = mqttPrefix + "sub."

	// Stream name for MQTT messages on a given account
	mqttStreamName          = "$MQTT_msgs"
	mqttStreamSubjectPrefix = mqttPrefix + "msgs."

	// Stream name for MQTT retained messages on a given account
	mqttRetainedMsgsStreamName    = "$MQTT_rmsgs"
	mqttRetainedMsgsStreamSubject = mqttPrefix + "rmsgs."

	// Stream name for MQTT sessions on a given account
	mqttSessStreamName          = "$MQTT_sess"
	mqttSessStreamSubjectPrefix = mqttPrefix + "sess."

	// Stream name prefix for MQTT sessions on a given account
	mqttSessionsStreamNamePrefix = "$MQTT_sess_"

	// Stream name and subject for incoming MQTT QoS2 messages
	mqttQoS2IncomingMsgsStreamName          = "$MQTT_qos2in"
	mqttQoS2IncomingMsgsStreamSubjectPrefix = mqttPrefix + "qos2.in."

	// Stream name and subjects for outgoing MQTT QoS (PUBREL) messages
	mqttOutStreamName               = "$MQTT_out"
	mqttOutSubjectPrefix            = mqttPrefix + "out."
	mqttPubRelSubjectPrefix         = mqttPrefix + "out.pubrel."
	mqttPubRelDeliverySubjectPrefix = mqttPrefix + "deliver.pubrel."
	mqttPubRelConsumerDurablePrefix = "$MQTT_PUBREL_"

	// As per spec, MQTT server may not redeliver QoS 1 and 2 messages to
	// clients, except after client reconnects. However, NATS Server will
	// redeliver unacknowledged messages after this default interval. This can
	// be changed with the server.Options.MQTT.AckWait option.
	mqttDefaultAckWait = 30 * time.Second

	// This is the default for the outstanding number of pending QoS 1
	// messages sent to a session with QoS 1 subscriptions.
	mqttDefaultMaxAckPending = 1024

	// A session's list of subscriptions cannot have a cumulative MaxAckPending
	// of more than this limit.
	mqttMaxAckTotalLimit = 0xFFFF

	// Prefix of the reply subject for JS API requests.
	mqttJSARepliesPrefix = mqttPrefix + "JSA."

	// Those are tokens that are used for the reply subject of JS API requests.
	// For instance "$MQTT.JSA.<node id>.SC.<number>" is the reply subject
	// for a request to create a stream (where <node id> is the server name hash),
	// while "$MQTT.JSA.<node id>.SL.<number>" is for a stream lookup, etc...
	mqttJSAIdTokenPos     = 3
	mqttJSATokenPos       = 4
	mqttJSAClientIDPos    = 5
	mqttJSAStreamCreate   = "SC"
	mqttJSAStreamUpdate   = "SU"
	mqttJSAStreamLookup   = "SL"
	mqttJSAStreamDel      = "SD"
	mqttJSAConsumerCreate = "CC"
	mqttJSAConsumerLookup = "CL"
	mqttJSAConsumerDel    = "CD"
	mqttJSAMsgStore       = "MS"
	mqttJSAMsgLoad        = "ML"
	mqttJSAMsgDelete      = "MD"
	mqttJSASessPersist    = "SP"
	mqttJSARetainedMsgDel = "RD"
	mqttJSAStreamNames    = "SN"

	// This is how long to keep a client in the flappers map before closing the
	// connection. This prevent quick reconnect from those clients that keep
	// wanting to connect with a client ID already in use.
	mqttSessFlappingJailDur = time.Second

	// This is how frequently the timer to cleanup the sessions flappers map is firing.
	mqttSessFlappingCleanupInterval = 5 * time.Second

	// Default retry delay if transfer of old session streams to new one fails
	mqttDefaultTransferRetry = 5 * time.Second

	// For Websocket URLs
	mqttWSPath = "/mqtt"

	mqttInitialPubHeader        = 16 // An overkill, should need 7 bytes max
	mqttProcessSubTooLong       = 100 * time.Millisecond
	mqttDefaultRetainedCacheTTL = 2 * time.Minute
	mqttRetainedTransferTimeout = 10 * time.Second
	mqttDefaultJSAPITimeout     = 5 * time.Second
	mqttRetainedFlagDelMarker   = '-'
)

const (
	sparkbNBIRTH = "NBIRTH"
	sparkbDBIRTH = "DBIRTH"
	sparkbNDEATH = "NDEATH"
	sparkbDDEATH = "DDEATH"
)

var (
	sparkbNamespaceTopicPrefix    = []byte("spBv1.0/")
	sparkbCertificatesTopicPrefix = []byte("$sparkplug/certificates/")
)

var (
	mqttPingResponse     = []byte{mqttPacketPingResp, 0x0}
	mqttProtoName        = []byte("MQTT")
	mqttOldProtoName     = []byte("MQIsdp")
	mqttSessJailDur      = mqttSessFlappingJailDur
	mqttFlapCleanItvl    = mqttSessFlappingCleanupInterval
	mqttRetainedCacheTTL = mqttDefaultRetainedCacheTTL
)

var (
	errMQTTNotWebsocketPort           = errors.New("MQTT clients over websocket must connect to the Websocket port, not the MQTT port")
	errMQTTTopicFilterCannotBeEmpty   = errors.New("topic filter cannot be empty")
	errMQTTMalformedVarInt            = errors.New("malformed variable int")
	errMQTTSecondConnectPacket        = errors.New("received a second CONNECT packet")
	errMQTTServerNameMustBeSet        = errors.New("mqtt requires server name to be explicitly set")
	errMQTTUserMixWithUsersNKeys      = errors.New("mqtt authentication username not compatible with presence of users/nkeys")
	errMQTTTokenMixWIthUsersNKeys     = errors.New("mqtt authentication token not compatible with presence of users/nkeys")
	errMQTTAckWaitMustBePositive      = errors.New("ack wait must be a positive value")
	errMQTTJSAPITimeoutMustBePositive = errors.New("JS API timeout must be a positive value")
	errMQTTStandaloneNeedsJetStream   = errors.New("mqtt requires JetStream to be enabled if running in standalone mode")
	errMQTTConnFlagReserved           = errors.New("connect flags reserved bit not set to 0")
	errMQTTWillAndRetainFlag          = errors.New("if Will flag is set to 0, Will Retain flag must be 0 too")
	errMQTTPasswordFlagAndNoUser      = errors.New("password flag set but username flag is not")
	errMQTTCIDEmptyNeedsCleanFlag     = errors.New("when client ID is empty, clean session flag must be set to 1")
	errMQTTEmptyWillTopic             = errors.New("empty Will topic not allowed")
	errMQTTEmptyUsername              = errors.New("empty user name not allowed")
	errMQTTTopicIsEmpty               = errors.New("topic cannot be empty")
	errMQTTPacketIdentifierIsZero     = errors.New("packet identifier cannot be 0")
	errMQTTUnsupportedCharacters      = errors.New("character not supported for MQTT topics")
	errMQTTInvalidSession             = errors.New("invalid MQTT session")
	errMQTTInvalidRetainFlags         = errors.New("invalid retained message flags")
	errMQTTSessionCollision           = errors.New("stored session does not match client ID")
	errMQTTInvalidPublishLength       = errors.New("invalid publish message, variable header exceeds remaining length")
	errMQTTMalformedProperties        = errors.New("malformed properties")
	errMQTTProtocolError              = errors.New("protocol error")
	errMQTTDuplicateProperty          = errors.New("duplicate property")
	errMQTTUnknownProperty            = errors.New("unknown property identifier")
	errMQTTPropertyNotAllowed         = errors.New("property not allowed for this packet type")
	errMQTTAuthMethodNotSupported     = errors.New("enhanced authentication (auth method) is not supported")
	errMQTTUnsupportedSubOption       = errors.New("unsupported MQTT 5.0 subscription option")
)

type srvMQTT struct {
	listener     net.Listener
	listenerErr  error
	authOverride bool
	sessmgr      mqttSessionManager
	// v5Enabled caches whether this server accepts MQTT 5.0 (max_protocol_version
	// == 5), set once at startup and read lock-free thereafter. It lets v5-only
	// machinery be skipped entirely on a 3.1.1-only server.
	v5Enabled bool
}

type mqttSessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*mqttAccountSessionManager // key is account name
}

type mqttAccountSessionManager struct {
	mu         sync.RWMutex
	sessions   map[string]*mqttSession                // key is MQTT client ID
	sessByHash map[string]*mqttSession                // key is MQTT client ID hash
	sessLocked map[string]struct{}                    // key is MQTT client ID and indicate that a session can not be taken by a new client at this time
	flappers   map[string]time.Time                   // When connection connects with client ID already in use
	flapTimer  *time.Timer                            // Timer to perform some cleanup of the flappers map
	retmsgs    *stree.SubjectTree[mqttRetainedMsgRef] // retained message metadata
	rmsCache   *sync.Map                              // map[subject]mqttRetainedMsg
	jsa        mqttJSA
	domainTk   string // Domain (with trailing "."), or possibly empty. This is added to session subject.

	// Degraded mode, set once at creation (read without lock): per-message TTL
	// could not be enabled on a pre-existing stream, so stored messages must
	// not carry a Nats-TTL header (JetStream would reject them). Delivery-side
	// expiry checks still apply; only storage reaping is lost.
	msgsStreamNoTTL  bool
	rmsgsStreamNoTTL bool
}

type mqttJSAResponse struct {
	reply string // will be used to map to the original request in jsa.NewRequestExMulti
	value any
}

type mqttJSA struct {
	mu        sync.Mutex
	id        string
	c         *client
	sendq     *ipQueue[*mqttJSPubMsg]
	rplyr     string
	replies   sync.Map // [string]chan *mqttJSAResponse
	nuid      *nuid.NUID
	quitCh    chan struct{}
	domain    string // Domain or possibly empty. This is added to session subject.
	domainSet bool   // covers if domain was set, even to empty
	timeout   time.Duration
}

type mqttJSPubMsg struct {
	subj  string
	reply string
	hdr   int
	msg   []byte
}

type mqttRetMsgDel struct {
	Subject string `json:"subject"`
	Seq     uint64 `json:"seq"`
}

type mqttSession struct {
	// subsMu is a "quick" version of the session lock, sufficient for the QoS0
	// callback. It only guarantees that a new subscription is initialized, and
	// its retained messages if any have been queued up for delivery. The QoS12
	// callback uses the session lock.
	mu     sync.Mutex
	subsMu sync.RWMutex

	id                     string // client ID
	idHash                 string // client ID hash
	c                      *client
	jsa                    *mqttJSA
	subs                   map[string]byte // Key is MQTT SUBSCRIBE filter, value is the subscription QoS
	cons                   map[string]*ConsumerConfig
	pubRelConsumer         *ConsumerConfig
	pubRelSubscribed       bool
	pubRelDeliverySubject  string
	pubRelDeliverySubjectB []byte
	pubRelSubject          string
	seq                    uint64

	// pendingPublish maps packet identifiers (PI) to JetStream ACK subjects for
	// QoS1 and 2 PUBLISH messages pending delivery to the session's client.
	pendingPublish map[uint16]*mqttPending

	// pendingPubRel maps PIs to JetStream ACK subjects for QoS2 PUBREL
	// messages pending delivery to the session's client.
	pendingPubRel map[uint16]*mqttPending

	// cpending maps delivery attempts (that come with a JS ACK subject) to
	// existing PIs.
	cpending map[string]map[uint64]uint16 // composite key: jsDur, sseq

	// "Last used" publish packet identifier (PI). starting point searching for the next available.
	last_pi uint16

	// Maximum number of pending acks for this session.
	maxp uint16
	// rmax is the current connection's MQTT 5.0 Receive Maximum: the max number
	// of unacknowledged QoS1/2 PUBLISH the server may have in flight to the
	// client. 0 means no client-imposed limit (3.1.1, or not sent). The
	// effective in-flight cap is min(maxp, rmax). Set on each CONNECT.
	rmax     uint16
	tmaxack  int
	clean    bool
	domainTk string
}

type mqttPersistedSession struct {
	Origin string                     `json:"origin,omitempty"`
	ID     string                     `json:"id,omitempty"`
	Clean  bool                       `json:"clean,omitempty"`
	Subs   map[string]byte            `json:"subs,omitempty"`
	Cons   map[string]*ConsumerConfig `json:"cons,omitempty"`
	PubRel *ConsumerConfig            `json:"pubrel,omitempty"`
}

type mqttRetainedMsg struct {
	Origin  string `json:"origin,omitempty"`
	Subject string `json:"subject,omitempty"`
	Topic   string `json:"topic,omitempty"`
	Msg     []byte `json:"msg,omitempty"`
	Flags   byte   `json:"flags,omitempty"`
	Source  string `json:"source,omitempty"`
	// Props is the raw MQTT 5.0 properties block captured from the retained
	// PUBLISH, forwarded to v5 subscribers when the message is replayed. Empty
	// for messages published by 3.1.1 clients or without properties.
	Props []byte `json:"props,omitempty"`

	// expires is the absolute deadline after which this retained message must no
	// longer be delivered, when it was published with an MQTT 5.0 Message Expiry
	// Interval. Zero when the message has no expiry. Persisted with the stored
	// message via the mqttNatsRetainedMessageExpiry header (not JSON). Spec5
	// [3.3.2.3.3].
	expires time.Time

	expiresFromCache time.Time
}

type mqttRetainedMsgRef struct {
	sseq uint64
}

// mqttSub contains fields associated with a MQTT subscription, and is added to
// the main subscription struct for MQTT message delivery subscriptions. The
// delivery callbacks may get invoked before sub.mqtt is set up, so they should
// acquire either sess.mu or sess.subsMu before accessing it.
type mqttSub struct {
	// The sub's QOS and the JS durable name. They can change when
	// re-subscribing, and are used in the delivery callbacks. They can be
	// quickly accessed using sess.subsMu.RLock, or under the main session lock.
	qos   byte
	jsDur string

	// Pending serialization of retained messages to be sent when subscription
	// is registered. The sub's delivery callbacks must wait until `prm` is
	// ready (can block on sess.mu for that, too).
	prm [][]byte

	// If this subscription needs to be checked for being reserved. E.g. '#' or
	// '*' or '*/'.  It is set up at the time of subscription and is immutable
	// after that.
	reserved bool
}

type mqtt struct {
	r    *mqttReader
	cp   *mqttConnectProto
	pp   *mqttPublish
	asm  *mqttAccountSessionManager // quick reference to account session manager, immutable after processConnect()
	sess *mqttSession               // quick reference to session, immutable after processConnect()
	cid  string                     // client ID

	// proto is the negotiated protocol level: mqttProtoLevel (3.1.1) or
	// mqttProtoLevel5 (5.0). Set during CONNECT parsing and immutable after.
	// It outlives individual packets so that ACK/DISCONNECT handlers running
	// long after CONNECT can select the proper wire framing.
	proto byte

	// maxPacketSize is the current connection's MQTT 5.0 Maximum Packet Size:
	// the largest PUBLISH (whole control packet) the client is willing to
	// accept. 0 means no client-imposed limit (3.1.1, or not sent). Set during
	// CONNECT and read lock-free on the delivery paths like proto. Unlike the
	// session's Receive Maximum (rmax), this lives on the per-connection client:
	// it must gate the QoS0 direct-delivery path, which runs without the session
	// lock. Spec5 [3.1.2.11.4].
	maxPacketSize uint32

	// cidGenerated is true when the client sent an empty client ID and the
	// server assigned one. For v5 it must be echoed back in the CONNACK as the
	// Assigned Client Identifier property. Spec5 [3.2.2.3.7].
	cidGenerated bool

	// rejectQoS2Pub tells the MQTT client to not accept QoS2 PUBLISH, instead
	// error and terminate the connection.
	rejectQoS2Pub bool

	// downgradeQOS2Sub tells the MQTT client to downgrade QoS2 SUBSCRIBE
	// requests to QoS1.
	downgradeQoS2Sub bool
}

// mqttProperties holds the parsed MQTT 5.0 variable-header properties for a
// packet. Only the fields needed by the current implementation are tracked;
// recognized-but-unused properties are validated then discarded. Spec
// [MQTT-2.2.2].
type mqttProperties struct {
	sessionExpiry    uint32
	receiveMax       uint16
	maxPacketSize    uint32
	topicAliasMax    uint16
	topicAlias       uint16
	willDelay        uint32
	messageExpiry    uint32
	serverKeepAlive  uint16
	maxQoS           byte
	payloadFormat    byte
	requestProblem   byte
	requestResponse  byte
	retainAvailable  byte
	wildcardSubAvail byte
	subIDAvail       byte
	sharedSubAvail   byte
	subIDs           []int
	assignedClientID string
	authMethod       string
	contentType      string
	responseTopic    string
	reasonString     string
	correlationData  []byte
	authData         []byte
	user             []mqttUserProperty
	// Tracks which scalar properties were present, so we can reject illegal
	// duplicates and tell "absent" apart from "explicit zero".
	present map[byte]bool
}

type mqttUserProperty struct {
	key   string
	value string
}

type mqttPending struct {
	sseq         uint64 // stream sequence
	jsAckSubject string // the ACK subject to send the ack to
	jsDur        string // JS durable name
}

type mqttConnectProto struct {
	rd    time.Duration
	will  *mqttWill
	flags byte
	// MQTT 5.0 CONNECT properties (nil for 3.1.1).
	props *mqttProperties
}

type mqttIOReader interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

type mqttReader struct {
	reader mqttIOReader
	buf    []byte
	pos    int
	pstart int
	pbuf   []byte
}

type mqttWriter struct {
	bytes.Buffer
}

type mqttWill struct {
	topic   []byte
	subject []byte
	mapped  []byte
	message []byte
	qos     byte
	retain  bool
	// MQTT 5.0 Will properties (nil for 3.1.1).
	props *mqttProperties
}

// mqttSharedSubPrefix is the MQTT 5.0 Shared Subscription topic filter prefix
// ("$share/{ShareName}/{filter}"). Shared subscriptions are not implemented.
var mqttSharedSubPrefix = []byte("$share/")

type mqttFilter struct {
	filter string
	qos    byte
	// v5 (UN)SUBACK reason code for this filter (zero value is success).
	reason byte
	// Used only for tracing and should not be used after parsing of (un)sub protocols.
	ttopic []byte
}

type mqttPublish struct {
	topic   []byte
	subject []byte
	mapped  []byte
	msg     []byte
	sz      int
	pi      uint16
	flags   byte
	// props is the raw MQTT 5.0 properties block (variable-int length prefix +
	// body, exactly as received on the wire), captured so it can be forwarded
	// unaltered to v5 subscribers. nil when absent or empty (3.1.1, or a v5
	// PUBLISH with no properties). Spec5 [3.3.2.3].
	props []byte
}

// When we re-encode incoming MQTT PUBLISH messages for NATS delivery, we add
// the following headers:
//   - "Nmqtt-Pub" (*always) indicates that the message originated from MQTT, and
//     contains the original message QoS.
//   - "Nmqtt-Subject" contains the original MQTT subject from mqttParsePub.
//   - "Nmqtt-Mapped" contains the mapping during mqttParsePub.
//
// When we submit a PUBREL for delivery, we add a "Nmqtt-PubRel" header that
// contains the PI.
const (
	// NATS header that indicates that the message originated from MQTT and
	// stores the published message QOS.
	mqttNatsHeader = "Nmqtt-Pub"

	// NATS headers to store retained message metadata (along with the original
	// message as binary).
	mqttNatsRetainedMessageTopic  = "Nmqtt-RTopic"
	mqttNatsRetainedMessageOrigin = "Nmqtt-ROrigin"
	mqttNatsRetainedMessageFlags  = "Nmqtt-RFlags"
	mqttNatsRetainedMessageSource = "Nmqtt-RSource"
	// Raw MQTT 5.0 properties block for a retained message (base64), so v5
	// properties are replayed to subscribers. Absent for older stored messages.
	mqttNatsRetainedMessageProps = "Nmqtt-RProps"

	// Absolute expiry deadline (Unix nanoseconds, decimal) for a retained message
	// that was published with an MQTT 5.0 Message Expiry Interval. Carried with
	// the stored message so the remaining interval can be computed on replay
	// regardless of which server (or cache) serves it. Absent when the retained
	// message has no expiry. Spec5 [3.3.2.3.3].
	mqttNatsRetainedMessageExpiry = "Nmqtt-RExp"

	// NATS header that indicates that the message is an MQTT PubRel and stores
	// the PI.
	mqttNatsPubRelHeader = "Nmqtt-PubRel"

	// NATS headers to store the original MQTT subject and the subject mapping.
	mqttNatsHeaderSubject = "Nmqtt-Subject"
	mqttNatsHeaderMapped  = "Nmqtt-Mapped"

	// NATS header carrying the raw MQTT 5.0 PUBLISH properties block
	// (base64-encoded, since the block is binary and NATS header values are
	// CRLF-delimited text) so end-to-end properties survive the NATS/JetStream
	// hop and can be re-emitted to v5 subscribers.
	mqttNatsHeaderProps = "Nmqtt-Props"
)

type mqttParsedPublishNATSHeader struct {
	qos     byte
	subject []byte
	mapped  []byte
	props   []byte // raw MQTT 5.0 properties block (decoded from Nmqtt-Props)
}

func (s *Server) startMQTT() {
	if s.isShuttingDown() {
		return
	}

	sopts := s.getOpts()
	o := &sopts.MQTT

	var hl net.Listener
	var err error

	port := o.Port
	if port == -1 {
		port = 0
	}
	hp := net.JoinHostPort(o.Host, strconv.Itoa(port))
	s.mu.Lock()
	s.mqtt.sessmgr.sessions = make(map[string]*mqttAccountSessionManager)
	s.mqtt.v5Enabled = o.MaxProtocolVersion >= mqttProtoLevel5
	hl, err = natsListen("tcp", hp)
	s.mqtt.listenerErr = err
	if err != nil {
		s.mu.Unlock()
		s.Fatalf("Unable to listen for MQTT connections: %v", err)
		return
	}
	if port == 0 {
		o.Port = hl.Addr().(*net.TCPAddr).Port
	}
	s.mqtt.listener = hl
	scheme := "mqtt"
	if o.TLSConfig != nil {
		scheme = "tls"
	}
	s.Noticef("Listening for MQTT clients on %s://%s:%d", scheme, o.Host, o.Port)
	if s.mqtt.v5Enabled {
		s.Warnf("MQTT 5.0 support is enabled but experimental: some v5 features " +
			"(session/will-delay expiry) are not yet honored")
	}
	go s.acceptConnections(hl, "MQTT", func(conn net.Conn) { s.createMQTTClient(conn, nil) }, nil)
	s.mu.Unlock()
}

// This is similar to createClient() but has some modifications specifi to MQTT clients.
// The comments have been kept to minimum to reduce code size. Check createClient() for
// more details.
func (s *Server) createMQTTClient(conn net.Conn, ws *websocket) *client {
	opts := s.getOpts()

	maxPay := int32(opts.MaxPayload)
	maxSubs := int32(opts.MaxSubs)
	if maxSubs == 0 {
		maxSubs = -1
	}
	now := time.Now()

	mqtt := &mqtt{
		rejectQoS2Pub:    opts.MQTT.rejectQoS2Pub,
		downgradeQoS2Sub: opts.MQTT.downgradeQoS2Sub,
	}
	c := &client{srv: s, nc: conn, mpay: maxPay, msubs: maxSubs, start: now, last: now, mqtt: mqtt, ws: ws}
	c.headers = true
	c.mqtt.pp = &mqttPublish{}
	// MQTT clients don't send NATS CONNECT protocols. So make it an "echo"
	// client, but disable verbose and pedantic (by not setting them).
	c.opts.Echo = true

	c.registerWithAccount(s.globalAccount())

	s.mu.Lock()
	// Check auth, override if applicable.
	authRequired := s.info.AuthRequired || s.mqtt.authOverride
	s.totalClients++
	s.mu.Unlock()

	c.mu.Lock()
	if authRequired {
		c.flags.set(expectConnect)
	}
	c.initClient()
	c.Debugf("Client connection created")
	c.mu.Unlock()

	s.mu.Lock()
	if !s.isRunning() || s.ldm {
		if s.isShuttingDown() {
			conn.Close()
		}
		s.mu.Unlock()
		return c
	}

	if opts.MaxConn < 0 || (opts.MaxConn > 0 && len(s.clients) >= opts.MaxConn) {
		s.mu.Unlock()
		c.maxConnExceeded()
		return nil
	}
	s.clients[c.cid] = c

	// Websocket TLS handshake is already done when getting to this function.
	tlsRequired := opts.MQTT.TLSConfig != nil && ws == nil
	s.mu.Unlock()

	c.mu.Lock()

	// In case connection has already been closed
	if c.isClosed() {
		c.mu.Unlock()
		c.closeConnection(WriteError)
		return nil
	}

	var pre []byte
	if tlsRequired && opts.AllowNonTLS {
		pre = make([]byte, 4)
		c.nc.SetReadDeadline(time.Now().Add(secondsToDuration(opts.MQTT.TLSTimeout)))
		n, _ := io.ReadFull(c.nc, pre[:])
		c.nc.SetReadDeadline(time.Time{})
		pre = pre[:n]
		if n > 0 && pre[0] == 0x16 {
			tlsRequired = true
		} else {
			tlsRequired = false
		}
	}

	if tlsRequired {
		if len(pre) > 0 {
			c.nc = &tlsMixConn{c.nc, bytes.NewBuffer(pre)}
			pre = nil
		}

		// Perform server-side TLS handshake.
		if err := c.doTLSServerHandshake(tlsHandshakeMQTT, opts.MQTT.TLSConfig, opts.MQTT.TLSTimeout, opts.MQTT.TLSPinnedCerts); err != nil {
			c.mu.Unlock()
			return nil
		}
	}

	if authRequired {
		timeout := opts.AuthTimeout
		// Possibly override with MQTT specific value.
		if opts.MQTT.AuthTimeout != 0 {
			timeout = opts.MQTT.AuthTimeout
		}
		c.setAuthTimer(secondsToDuration(timeout))
	}

	// No Ping timer for MQTT clients...

	s.startGoRoutine(func() { c.readLoop(pre) })
	s.startGoRoutine(func() { c.writeLoop() })

	if tlsRequired {
		c.Debugf("TLS handshake complete")
		cs := c.nc.(*tls.Conn).ConnectionState()
		c.Debugf("TLS version %s, cipher suite %s", tlsVersion(cs.Version), tls.CipherSuiteName(cs.CipherSuite))
	}

	c.mu.Unlock()

	return c
}

// Given the mqtt options, we check if any auth configuration
// has been provided. If so, possibly create users/nkey users and
// store them in s.mqtt.users/nkeys.
// Also update a boolean that indicates if auth is required for
// mqtt clients.
// Server lock is held on entry.
func (s *Server) mqttConfigAuth(opts *MQTTOpts) {
	mqtt := &s.mqtt
	// If any of those is specified, we consider that there is an override.
	mqtt.authOverride = opts.Username != _EMPTY_ || opts.Token != _EMPTY_ || opts.NoAuthUser != _EMPTY_
}

// Validate the mqtt related options.
func validateMQTTOptions(o *Options) error {
	mo := &o.MQTT
	// If no port is defined, we don't care about other options
	if mo.Port == 0 {
		return nil
	}
	// We have to force the server name to be explicitly set and be unique when
	// in cluster mode.
	if o.ServerName == _EMPTY_ && (o.Cluster.Port != 0 || o.Gateway.Port != 0) {
		return errMQTTServerNameMustBeSet
	}
	// If there is a NoAuthUser, we need to have Users defined and
	// the user to be present.
	if mo.NoAuthUser != _EMPTY_ {
		if err := validateNoAuthUser(o, mo.NoAuthUser); err != nil {
			return err
		}
	}
	// Token/Username not possible if there are users/nkeys
	if len(o.Users) > 0 || len(o.Nkeys) > 0 {
		if mo.Username != _EMPTY_ {
			return errMQTTUserMixWithUsersNKeys
		}
		if mo.Token != _EMPTY_ {
			return errMQTTTokenMixWIthUsersNKeys
		}
	}
	if mo.AckWait < 0 {
		return errMQTTAckWaitMustBePositive
	}
	if mo.JSAPITimeout < 0 {
		return errMQTTJSAPITimeoutMustBePositive
	}
	// Validate the max protocol version for all configuration paths (config
	// file parsing already checks this, but programmatic Options do not). 0
	// means default (3.1.1 only); 4 and 5 are the supported explicit values.
	// Any other value would make the runtime cap reject even 3.1.1 connects.
	switch mo.MaxProtocolVersion {
	case 0, mqttProtoLevel, mqttProtoLevel5:
	default:
		return fmt.Errorf("mqtt max_protocol_version must be 0 (default), 4 or 5, got %d", mo.MaxProtocolVersion)
	}
	// If strictly standalone and there is no JS enabled, then it won't work...
	// For leafnodes, we could either have remote(s) and it would be ok, or no
	// remote but accept from a remote side that has "hub" property set, which
	// then would ok too. So we fail only if we have no leafnode config at all.
	if !o.JetStream && o.Cluster.Port == 0 && o.Gateway.Port == 0 &&
		o.LeafNode.Port == 0 && len(o.LeafNode.Remotes) == 0 {
		return errMQTTStandaloneNeedsJetStream
	}
	if err := validatePinnedCerts(mo.TLSPinnedCerts); err != nil {
		return fmt.Errorf("mqtt: %v", err)
	}
	if mo.ConsumerReplicas > 0 && mo.StreamReplicas > 0 && mo.ConsumerReplicas > mo.StreamReplicas {
		return fmt.Errorf("mqtt: consumer_replicas (%v) cannot be higher than stream_replicas (%v)",
			mo.ConsumerReplicas, mo.StreamReplicas)
	}
	return nil
}

// Returns true if this connection is from a MQTT client.
// Lock held on entry.
func (c *client) isMqtt() bool {
	return c.mqtt != nil
}

// If this is an MQTT client, returns the session client ID,
// otherwise returns the empty string.
// Lock held on entry
func (c *client) getMQTTClientID() string {
	if !c.isMqtt() {
		return _EMPTY_
	}
	return c.mqtt.cid
}

// Parse protocols inside the given buffer.
// This is invoked from the readLoop.
func (c *client) mqttParse(buf []byte) error {
	c.mu.Lock()
	s := c.srv
	trace := c.trace
	connected := c.flags.isSet(connectReceived)
	mqtt := c.mqtt
	r := mqtt.r
	var rd time.Duration
	if mqtt.cp != nil {
		rd = mqtt.cp.rd
		if rd > 0 {
			r.reader.SetReadDeadline(time.Time{})
		}
	}
	hasMappings := c.in.flags.isSet(hasMappings)
	c.mu.Unlock()

	r.reset(buf)

	var err error
	var b byte
	var pl int
	var complete bool

	for err == nil && r.hasMore() {

		// Keep track of the starting of the packet, in case we have a partial
		r.pstart = r.pos

		// Read packet type and flags
		if b, err = r.readByte("packet type"); err != nil {
			break
		}

		// Packet type
		pt := b & mqttPacketMask

		// If client was not connected yet, the first packet must be
		// a mqttPacketConnect otherwise we fail the connection.
		if !connected && pt != mqttPacketConnect {
			// If the buffer indicates that it may be a websocket handshake
			// but the client is not websocket, it means that the client
			// connected to the MQTT port instead of the Websocket port.
			if bytes.HasPrefix(buf, []byte("GET ")) && !c.isWebsocket() {
				err = errMQTTNotWebsocketPort
			} else {
				err = fmt.Errorf("the first packet should be a CONNECT (%v), got %v", mqttPacketConnect, pt)
			}
			break
		}
		if err = mqttCheckFixedHeaderFlags(pt, b&mqttPacketFlagMask); err != nil {
			break
		}

		maxLen := int32(jwt.NoLimit)
		if !connected {
			maxLen = atomic.LoadInt32(&c.mpay)
		}
		pl, complete, err = r.readPacketLen(maxLen)
		if err != nil || !complete {
			if err == ErrMaxPayload {
				c.maxPayloadViolation(pl, maxLen)
			}
			break
		}
		if err = mqttCheckRemainingLength(pt, c.mqtt.proto, pl); err != nil {
			break
		}

		switch pt {
		// Packets that we receive back when we act as the "sender": PUBACK,
		// PUBREC, PUBCOMP.
		case mqttPacketPubAck:
			var pi uint16
			pi, _, err = mqttParsePubResponsePacket(r, c.mqtt.proto, pl)
			if trace {
				c.traceInOp("PUBACK", errOrTrace(err, fmt.Sprintf("pi=%v", pi)))
			}
			if err == nil {
				err = c.mqttProcessPubAck(pi)
			}

		case mqttPacketPubRec:
			var pi uint16
			var reason byte
			pi, reason, err = mqttParsePubResponsePacket(r, c.mqtt.proto, pl)
			if trace {
				c.traceInOp("PUBREC", errOrTrace(err, fmt.Sprintf("pi=%v", pi)))
			}
			if err == nil {
				err = c.mqttProcessPubRec(pi, reason)
			}

		case mqttPacketPubComp:
			var pi uint16
			pi, _, err = mqttParsePubResponsePacket(r, c.mqtt.proto, pl)
			if trace {
				c.traceInOp("PUBCOMP", errOrTrace(err, fmt.Sprintf("pi=%v", pi)))
			}
			if err == nil {
				c.mqttProcessPubComp(pi)
			}

		// Packets where we act as the "receiver": PUBLISH, PUBREL, SUBSCRIBE, UNSUBSCRIBE.
		case mqttPacketPub:
			pp := c.mqtt.pp
			pp.flags = b & mqttPacketFlagMask
			err = c.mqttParsePub(r, pl, pp, hasMappings)
			if trace {
				c.traceInOp("PUBLISH", errOrTrace(err, mqttPubTrace(pp)))
				if err == nil {
					c.mqttTraceMsg(pp.msg)
				}
			}
			if err == nil {
				err = s.mqttProcessPub(c, pp, trace)
			}

		case mqttPacketPubRel:
			var pi uint16
			pi, _, err = mqttParsePubResponsePacket(r, c.mqtt.proto, pl)
			if trace {
				c.traceInOp("PUBREL", errOrTrace(err, fmt.Sprintf("pi=%v", pi)))
			}
			if err == nil {
				err = s.mqttProcessPubRel(c, pi, trace)
			}

		case mqttPacketSub:
			var pi uint16 // packet identifier
			var filters []*mqttFilter
			var subs []*subscription
			pi, filters, err = c.mqttParseSubs(r, b, pl)
			if trace {
				c.traceInOp("SUBSCRIBE", errOrTrace(err, mqttSubscribeTrace(pi, filters)))
			}
			if err == nil {
				subs, err = c.mqttProcessSubs(filters)
				if err == nil && trace {
					c.traceOutOp("SUBACK", []byte(fmt.Sprintf("pi=%v", pi)))
				}
			}
			if err == nil {
				c.mqttEnqueueSubAck(pi, filters)
				c.mqttSendRetainedMsgsToNewSubs(subs)
			}

		case mqttPacketUnsub:
			var pi uint16 // packet identifier
			var filters []*mqttFilter
			pi, filters, err = c.mqttParseUnsubs(r, b, pl)
			if trace {
				c.traceInOp("UNSUBSCRIBE", errOrTrace(err, mqttUnsubscribeTrace(pi, filters)))
			}
			if err == nil {
				err = c.mqttProcessUnsubs(filters)
				if err == nil && trace {
					c.traceOutOp("UNSUBACK", []byte(fmt.Sprintf("pi=%v", pi)))
				}
			}
			if err == nil {
				c.mqttEnqueueUnsubAck(pi, filters)
			}

		// Packets that we get both as a receiver and sender: PING, CONNECT, DISCONNECT
		case mqttPacketPing:
			if trace {
				c.traceInOp("PINGREQ", nil)
			}
			c.mqttEnqueuePingResp()
			if trace {
				c.traceOutOp("PINGRESP", nil)
			}

		case mqttPacketConnect:
			// It is an error to receive a second connect packet
			if connected {
				err = errMQTTSecondConnectPacket
				break
			}
			var rc byte
			var cp *mqttConnectProto
			var sessp bool
			start := r.pos
			rc, cp, err = c.mqttParseConnect(r, hasMappings)
			// CONNECT has no trailing length check of its own; a lying
			// properties length would silently desync the packet stream.
			if err == nil && rc == 0 && r.pos-start != pl {
				err = fmt.Errorf("connect packet length mismatch: consumed %v bytes, remaining length is %v", r.pos-start, pl)
			}
			// Add the client id to the client's string, regardless of error.
			// We may still get the client_id if the call above fails somewhere
			// after parsing the client ID itself.
			c.ncs.Store(fmt.Sprintf("%s - %q", c, c.mqtt.cid))
			if trace && cp != nil {
				c.traceInOp("CONNECT", errOrTrace(err, c.mqttConnectTrace(cp)))
			}
			if rc != 0 {
				c.mqttEnqueueConnAck(rc, sessp)
				if trace {
					c.traceOutOp("CONNACK", []byte(fmt.Sprintf("sp=%v rc=%v", sessp, rc)))
				}
			} else if err != nil {
				// A malformed CONNECT has no return code. v5 expects a CONNACK
				// with the failure reason before the close; 3.1.1 just closes.
				// Spec5 [3.1.4.1], [MQTT-3.1.2-19].
				if c.mqtt.proto == mqttProtoLevel5 {
					reason := mqttConnAckReasonFromConnectErr(err)
					c.mqttEnqueueConnAck(reason, false)
					if trace {
						c.traceOutOp("CONNACK", []byte(fmt.Sprintf("sp=%v rc=%v", false, reason)))
					}
				}
			} else {
				if err = s.mqttProcessConnect(c, cp, trace); err != nil {
					err = fmt.Errorf("unable to connect: %v", err)
					// If the success CONNACK already went out, mark connected so
					// the v5 error path below sends a DISCONNECT with the reason
					// instead of a bare close. Read under the client lock: the
					// writeLoop mutates c.flags while flushing that CONNACK.
					c.mu.Lock()
					connected = c.flags.isSet(connectReceived)
					c.mu.Unlock()
				} else {
					// Add this debug statement so users running in Debug mode
					// will have the client id printed here for the first time.
					c.Debugf("Client connected")
					connected = true
					rd = cp.rd
				}
			}

		case mqttPacketDisconnect:
			// By default a DISCONNECT discards the Will. Spec [MQTT-3.1.2-8].
			discardWill := true
			if c.mqtt.proto == mqttProtoLevel5 && pl > 0 {
				// v5 DISCONNECT carries a reason code and optional properties.
				// Spec5 [3.14]. Reason 0x04 ("Disconnect with Will Message")
				// instructs the server to publish the Will instead.
				var rcode byte
				if rcode, err = r.readByte("disconnect reason code"); err != nil {
					break
				}
				if pl > 1 {
					if _, err = r.readProperties(mqttPacketDisconnect); err != nil {
						break
					}
				}
				if rcode == mqttReasonDisconnectWithWill {
					discardWill = false
				}
			}
			if trace {
				c.traceInOp("DISCONNECT", nil)
			}
			if discardWill {
				c.mu.Lock()
				if c.mqtt.cp != nil {
					c.mqtt.cp.will = nil
				}
				c.mu.Unlock()
			}
			s.mqttHandleClosedClient(c)
			c.closeConnection(ClientClosed)
			return nil

		default:
			err = fmt.Errorf("received unknown packet type %d", pt>>4)
		}
	}
	if err == nil && rd > 0 {
		r.reader.SetReadDeadline(time.Now().Add(rd))
	} else if err != nil && connected && c.mqtt.proto == mqttProtoLevel5 {
		// Best-effort: tell the v5 client why we are about to close. The read
		// loop closes the connection right after this returns.
		c.mqttEnqueueDisconnect(mqttDisconnectReasonFromErr(err))
	}
	return err
}

func mqttCheckFixedHeaderFlags(packetType, flags byte) error {
	var expected byte
	switch packetType {
	case mqttPacketConnect, mqttPacketPubAck, mqttPacketPubRec, mqttPacketPubComp,
		mqttPacketPing, mqttPacketDisconnect:
		expected = 0
	case mqttPacketPubRel, mqttPacketSub, mqttPacketUnsub:
		expected = 0x2
	case mqttPacketPub:
		return nil
	default:
		return nil
	}
	if flags != expected {
		return fmt.Errorf("invalid fixed header flags %x for packet type %x", flags, packetType)
	}
	return nil
}

func mqttCheckRemainingLength(packetType, proto byte, pl int) error {
	v5 := proto == mqttProtoLevel5
	var expected int
	switch packetType {
	case mqttPacketConnect, mqttPacketPub, mqttPacketSub, mqttPacketUnsub:
		return nil
	case mqttPacketPubAck, mqttPacketPubRec, mqttPacketPubRel, mqttPacketPubComp:
		if v5 {
			// v5: packet identifier (2) + optional reason code + optional
			// properties. Spec5 [3.4.2.1].
			if pl < 2 {
				return fmt.Errorf("invalid remaining length %d for packet type %x", pl, packetType)
			}
			return nil
		}
		expected = 2
	case mqttPacketDisconnect:
		if v5 {
			// v5: 0 (normal disconnect) or reason code + optional properties.
			// Spec5 [3.14.2.1].
			return nil
		}
		expected = 0
	case mqttPacketPing:
		expected = 0
	default:
		return nil
	}
	if pl != expected {
		return fmt.Errorf("invalid remaining length %d for packet type %x", pl, packetType)
	}
	return nil
}

func (c *client) mqttTraceMsg(msg []byte) {
	maxTrace := c.srv.getOpts().MaxTracedMsgLen
	if maxTrace > 0 && len(msg) > maxTrace {
		c.Tracef("<<- MSG_PAYLOAD: [\"%s...\"]", msg[:maxTrace])
	} else {
		c.Tracef("<<- MSG_PAYLOAD: [%q]", msg)
	}
}

// The MQTT client connection has been closed, or the DISCONNECT packet was received.
// For a "clean" session, we will delete the session, otherwise, simply removing
// the binding. We will also send the "will" message if applicable.
//
// Runs from the client's readLoop.
// No lock held on entry.
func (s *Server) mqttHandleClosedClient(c *client) {
	c.mu.Lock()
	asm := c.mqtt.asm
	sess := c.mqtt.sess
	c.mu.Unlock()

	// If asm or sess are nil, it means that we have failed a client
	// before it was associated with a session, so nothing more to do.
	if asm == nil || sess == nil {
		return
	}

	// Add this session to the locked map for the rest of the execution.
	if err := asm.lockSession(sess, c); err != nil {
		return
	}
	defer asm.unlockSession(sess)

	asm.mu.Lock()
	// Clear the client from the session, but session may stay.
	sess.mu.Lock()
	sess.c = nil
	doClean := sess.clean
	sess.mu.Unlock()
	// If it was a clean session, then we remove from the account manager,
	// and we will call clear() outside of any lock.
	if doClean {
		asm.removeSession(sess, false)
	}
	// Remove in case it was in the flappers map.
	asm.removeSessFromFlappers(sess.id)
	asm.mu.Unlock()

	// This needs to be done outside of any lock.
	if doClean {
		if err := sess.clear(true); err != nil {
			c.Errorf(err.Error())
		}
	}

	// Now handle the "will". This function will be a no-op if there is no "will" to send.
	s.mqttHandleWill(c)
}

// Updates the MaxAckPending for all MQTT sessions, updating the
// JetStream consumers and updating their max ack pending and forcing
// a expiration of pending messages.
//
// Runs from a server configuration reload routine.
// No lock held on entry.
func (s *Server) mqttUpdateMaxAckPending(newmaxp uint16) {
	msm := &s.mqtt.sessmgr
	s.accounts.Range(func(k, _ any) bool {
		accName := k.(string)
		msm.mu.RLock()
		asm := msm.sessions[accName]
		msm.mu.RUnlock()
		if asm == nil {
			// Move to next account
			return true
		}
		asm.mu.RLock()
		for _, sess := range asm.sessions {
			sess.mu.Lock()
			sess.maxp = newmaxp
			sess.mu.Unlock()
		}
		asm.mu.RUnlock()
		return true
	})
}

func (s *Server) mqttGetJSAForAccount(acc string) *mqttJSA {
	sm := &s.mqtt.sessmgr

	sm.mu.RLock()
	asm := sm.sessions[acc]
	sm.mu.RUnlock()

	if asm == nil {
		return nil
	}

	asm.mu.RLock()
	jsa := &asm.jsa
	asm.mu.RUnlock()
	return jsa
}

func (s *Server) mqttStoreQoSMsgForAccountOnNewSubject(hdr int, msg []byte, acc, subject string) {
	if s == nil || hdr <= 0 {
		return
	}
	h := mqttParsePublishNATSHeader(msg[:hdr])
	if h == nil || h.qos == 0 {
		return
	}
	jsa := s.mqttGetJSAForAccount(acc)
	if jsa == nil {
		return
	}
	jsa.storeMsg(mqttStreamSubjectPrefix+subject, hdr, msg)
}

func mqttParsePublishNATSHeader(headerBytes []byte) *mqttParsedPublishNATSHeader {
	if len(headerBytes) == 0 {
		return nil
	}

	pubValue := getHeader(mqttNatsHeader, headerBytes)
	if len(pubValue) == 0 {
		return nil
	}
	h := &mqttParsedPublishNATSHeader{
		qos:     pubValue[0] - '0',
		subject: getHeader(mqttNatsHeaderSubject, headerBytes),
		mapped:  getHeader(mqttNatsHeaderMapped, headerBytes),
	}
	// MQTT 5.0 properties block, carried base64-encoded. This header can come
	// from an untrusted source (a NATS publisher can set Nmqtt-Pub/Nmqtt-Props
	// on a message an MQTT client is subscribed to), so the decoded block is
	// re-validated before it may be forwarded verbatim into an outbound PUBLISH
	// (see mqttValidateForwardProps). Best effort: anything invalid is simply
	// dropped, never a delivery failure and never a malformed outbound packet.
	if enc := getHeader(mqttNatsHeaderProps, headerBytes); len(enc) > 0 {
		if raw, err := base64.StdEncoding.DecodeString(string(enc)); err == nil {
			h.props = mqttValidateForwardProps(raw)
		}
	}
	return h
}

// mqttValidateForwardProps returns raw only if it is a well-formed MQTT 5.0
// properties block that is safe to forward to a subscriber: it must parse
// cleanly with no trailing bytes and must not contain a Topic Alias (hop-by-hop,
// never forwarded) or a Subscription Identifier (unsupported; disallowed in the
// PUBLISH context). Otherwise it returns nil so the message is delivered
// without properties. This protects against a crafted Nmqtt-Props header from a
// non-MQTT publisher making the server emit a malformed or forbidden PUBLISH.
func mqttValidateForwardProps(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	r := &mqttReader{}
	r.reset(raw)
	props, err := r.readProperties(mqttPacketPub)
	if err != nil || r.hasMore() {
		return nil
	}
	// Subscription Identifier is already rejected by readProperties (not allowed
	// in the PUBLISH context); Topic Alias parses but must not be forwarded.
	if props != nil && props.present[mqttPropTopicAlias] {
		return nil
	}
	return raw
}

// mqttVarIntFromSlice decodes an MQTT variable byte integer from the front of b.
// It returns the value and the number of bytes consumed, or (0, -1) if b does
// not begin with a complete, valid varint. Spec5 [1.5.5].
func mqttVarIntFromSlice(b []byte) (int, int) {
	m, v := 1, 0
	for n := 0; n < len(b) && n < 4; n++ {
		d := b[n]
		v += int(d&0x7f) * m
		if d&0x80 == 0 {
			return v, n + 1
		}
		m *= 0x80
	}
	return 0, -1
}

// mqttMessageExpiryOffset walks a well-formed MQTT 5.0 properties block (length
// prefix + body) and returns the byte offset of the 4-byte Message Expiry
// Interval value within it, or -1 if the block carries no Message Expiry
// Interval or cannot be walked. The block is expected to have already been
// validated (by readProperties / mqttValidateForwardProps), so property lengths
// are trusted; anything unexpected returns -1 rather than risk a bad rewrite.
func mqttMessageExpiryOffset(props []byte) int {
	plen, n := mqttVarIntFromSlice(props)
	if n < 0 {
		return -1
	}
	i, end := n, n+plen
	if end > len(props) {
		return -1
	}
	for i < end {
		prop := props[i]
		i++
		switch prop {
		case mqttPropMessageExpiry:
			if i+4 > end {
				return -1
			}
			return i
		case mqttPropPayloadFormat, mqttPropRequestProblemInfo, mqttPropRequestResponseInfo,
			mqttPropMaxQoS, mqttPropRetainAvailable, mqttPropWildcardSubAvailable,
			mqttPropSubIDAvailable, mqttPropSharedSubAvailable:
			i++
		case mqttPropServerKeepAlive, mqttPropReceiveMaximum, mqttPropTopicAliasMax,
			mqttPropTopicAlias:
			i += 2
		case mqttPropSessionExpiry, mqttPropWillDelay, mqttPropMaxPacketSize:
			i += 4
		case mqttPropContentType, mqttPropResponseTopic, mqttPropAssignedClientID,
			mqttPropAuthMethod, mqttPropResponseInfo, mqttPropServerReference,
			mqttPropReasonString, mqttPropCorrelationData, mqttPropAuthData:
			if i+2 > end {
				return -1
			}
			i += 2 + int(binary.BigEndian.Uint16(props[i:]))
		case mqttPropUserProperty:
			// Two length-prefixed strings (key then value).
			for k := 0; k < 2; k++ {
				if i+2 > end {
					return -1
				}
				i += 2 + int(binary.BigEndian.Uint16(props[i:]))
			}
		case mqttPropSubscriptionID:
			_, m := mqttVarIntFromSlice(props[i:])
			if m < 0 {
				return -1
			}
			i += m
		default:
			return -1
		}
		if i > end {
			return -1
		}
	}
	return -1
}

// mqttMessageExpiry returns the Message Expiry Interval (seconds) carried in a
// raw MQTT 5.0 properties block and whether the property was present. The two
// differ semantically: an absent property means the message never expires,
// whereas an explicit value of 0 means it expires immediately. Spec5 [3.3.2.3.3].
func mqttMessageExpiry(props []byte) (uint32, bool) {
	off := mqttMessageExpiryOffset(props)
	if off < 0 {
		return 0, false
	}
	return binary.BigEndian.Uint32(props[off:]), true
}

// mqttMessageExpiryTTL returns the JetStream per-message TTL (seconds) to apply
// to a stored message given its properties: 0 when the message has no expiry
// (never reaped by TTL), otherwise at least 1 (JetStream's minimum). Flooring an
// explicit expiry of 0 to 1s ensures an "expire immediately" message is still
// reaped rather than kept forever; onward delivery is additionally gated by
// mqttForwardExpiry. Spec5 [3.3.2.3.3].
func mqttMessageExpiryTTL(props []byte) uint32 {
	if me, ok := mqttMessageExpiry(props); ok {
		if me < 1 {
			return 1
		}
		return me
	}
	return 0
}

// mqttSetMessageExpiry returns a copy of the raw MQTT 5.0 properties block with
// the Message Expiry Interval value replaced by rem. If the block carries no
// Message Expiry Interval, props is returned unchanged (no copy), preserving the
// verbatim fast path for messages that do not use expiry. Spec5 [3.3.2.3.3].
func mqttSetMessageExpiry(props []byte, rem uint32) []byte {
	off := mqttMessageExpiryOffset(props)
	if off < 0 {
		return props
	}
	out := make([]byte, len(props))
	copy(out, props)
	binary.BigEndian.PutUint32(out[off:], rem)
	return out
}

// mqttForwardExpiry computes the outbound properties for a stored v5 PUBLISH,
// honoring the MQTT 5.0 Message Expiry Interval given the message's JetStream
// store time (storeUnixNano). It returns the (possibly rewritten) properties and
// whether the message has already expired. Spec5 [3.3.2.3.3]: the PUBLISH sent
// onward MUST carry the interval reduced by the time waited in the server; if
// the interval has elapsed before onward delivery the server MUST NOT deliver
// the message and MUST drop its stored copy. Returns props unchanged when there
// is no expiry to adjust. Elapsed time is measured on this server's wall clock;
// as with JetStream per-message TTLs, accuracy across a cluster assumes
// synchronized clocks.
func mqttForwardExpiry(props []byte, storeUnixNano int64) (out []byte, expired bool) {
	off := mqttMessageExpiryOffset(props)
	if off < 0 {
		return props, false
	}
	orig := int64(binary.BigEndian.Uint32(props[off:]))
	// An explicit interval of 0 means the message expires immediately: it is
	// already expired for any onward (stored) delivery, whatever the elapsed
	// time. Checked before the elapsed/store-time guards so a same-second
	// delivery cannot forward it. Spec5 [3.3.2.3.3].
	if orig == 0 {
		return props, true
	}
	if storeUnixNano <= 0 {
		return props, false
	}
	elapsed := (time.Now().UnixNano() - storeUnixNano) / int64(time.Second)
	if elapsed <= 0 {
		return props, false
	}
	if elapsed >= orig {
		return props, true
	}
	out = make([]byte, len(props))
	copy(out, props)
	binary.BigEndian.PutUint32(out[off:], uint32(orig-elapsed))
	return out, false
}

func mqttParsePubRelNATSHeader(headerBytes []byte) uint16 {
	if len(headerBytes) == 0 {
		return 0
	}

	pubrelValue := getHeader(mqttNatsPubRelHeader, headerBytes)
	if len(pubrelValue) == 0 {
		return 0
	}
	pi, _ := strconv.ParseUint(string(pubrelValue), 10, 16)
	return uint16(pi)
}

// Returns the MQTT sessions manager for a given account.
// If new, creates the required JetStream streams/consumers
// for handling of sessions and messages.
func (s *Server) getOrCreateMQTTAccountSessionManager(c *client) (*mqttAccountSessionManager, error) {
	sm := &s.mqtt.sessmgr

	c.mu.Lock()
	acc := c.acc
	c.mu.Unlock()
	accName := acc.GetName()

	sm.mu.RLock()
	asm, ok := sm.sessions[accName]
	sm.mu.RUnlock()

	if ok {
		return asm, nil
	}

	// We will pass the quitCh to the account session manager if we happen to create it.
	s.mu.Lock()
	quitCh := s.quitCh
	s.mu.Unlock()

	// Not found, now take the write lock and check again
	sm.mu.Lock()
	defer sm.mu.Unlock()
	asm, ok = sm.sessions[accName]
	if ok {
		return asm, nil
	}
	// Need to create one here.
	asm, err := s.mqttCreateAccountSessionManager(acc, quitCh)
	if err != nil {
		return nil, err
	}
	sm.sessions[accName] = asm
	return asm, nil
}

// Creates JS streams/consumers for handling of sessions and messages for this account.
//
// Global session manager lock is held on entry.
func (s *Server) mqttCreateAccountSessionManager(acc *Account, quitCh chan struct{}) (*mqttAccountSessionManager, error) {
	var err error

	accName := acc.GetName()

	opts := s.getOpts()
	c := s.createInternalAccountClient()
	c.acc = acc

	id := s.NodeName()

	mqttJSAPITimeout := opts.MQTT.JSAPITimeout
	if mqttJSAPITimeout == 0 {
		mqttJSAPITimeout = mqttDefaultJSAPITimeout
	}

	replicas := opts.MQTT.StreamReplicas
	if replicas <= 0 {
		replicas = s.mqttDetermineReplicas()
	}
	qname := fmt.Sprintf("[ACC:%s] MQTT ", accName)
	as := &mqttAccountSessionManager{
		sessions:   make(map[string]*mqttSession),
		sessByHash: make(map[string]*mqttSession),
		sessLocked: make(map[string]struct{}),
		flappers:   make(map[string]time.Time),
		jsa: mqttJSA{
			id:      id,
			c:       c,
			rplyr:   mqttJSARepliesPrefix + id + ".",
			sendq:   newIPQueue[*mqttJSPubMsg](s, qname+"send"),
			nuid:    nuid.New(),
			quitCh:  quitCh,
			timeout: mqttJSAPITimeout,
		},
		rmsCache: &sync.Map{},
	}
	// TODO record domain name in as here

	// The domain to communicate with may be required for JS calls.
	// Search from specific (per account setting) to generic (mqtt setting)
	if opts.JsAccDefaultDomain != nil {
		if d, ok := opts.JsAccDefaultDomain[accName]; ok {
			if d != _EMPTY_ {
				as.jsa.domain = d
			}
			as.jsa.domainSet = true
		}
		// in case domain was set to empty, check if there are more generic domain overwrites
	}
	if as.jsa.domain == _EMPTY_ {
		if d := opts.MQTT.JsDomain; d != _EMPTY_ {
			as.jsa.domain = d
			as.jsa.domainSet = true
		}
	}
	// We need to include the domain in the subject prefix used to store sessions in the $MQTT_sess stream.
	if as.jsa.domainSet {
		if as.jsa.domain != _EMPTY_ {
			as.domainTk = as.jsa.domain + "."
		}
	} else if d := s.getOpts().JetStreamDomain; d != _EMPTY_ {
		as.domainTk = d + "."
	}
	if as.jsa.domainSet {
		s.Noticef("Creating MQTT streams/consumers with replicas %v for account %q in domain %q", replicas, accName, as.jsa.domain)
	} else {
		s.Noticef("Creating MQTT streams/consumers with replicas %v for account %q", replicas, accName)
	}

	var subs []*subscription
	var success bool
	closeCh := make(chan struct{})

	defer func() {
		if success {
			return
		}
		for _, sub := range subs {
			c.processUnsub(sub.sid)
		}
		close(closeCh)
	}()

	// We create all subscriptions before starting the go routine that will do
	// sends otherwise we could get races.
	// Note that using two different clients (one for the subs, one for the
	// sends) would cause other issues such as registration of recent subs in
	// the "sub" client would be invisible to the check for GW routed replies
	// (shouldMapReplyForGatewaySend) since the client there would be the "sender".

	jsa := &as.jsa
	sid := int64(1)
	// This is a subscription that will process all JS API replies. We could split to
	// individual subscriptions if needed, but since there is a bit of common code,
	// that seemed like a good idea to be all in one place.
	if err := as.createSubscription(jsa.rplyr+">",
		as.processJSAPIReplies, &sid, &subs); err != nil {
		return nil, err
	}

	// We will listen for replies to session persist requests so that we can
	// detect the use of a session with the same client ID anywhere in the cluster.
	//   `$MQTT.JSA.{js-id}.SP.{client-id-hash}.{uuid}`
	if err := as.createSubscription(mqttJSARepliesPrefix+"*."+mqttJSASessPersist+".*.*",
		as.processSessionPersist, &sid, &subs); err != nil {
		return nil, err
	}

	// We create the subscription on "$MQTT.sub.<nuid>" to limit the subjects
	// that a user would allow permissions on.
	rmsubj := mqttSubPrefix + nuid.Next()
	if err := as.createSubscription(rmsubj, as.processRetainedMsg, &sid, &subs); err != nil {
		return nil, err
	}

	// Create a subscription to be notified of retained messages delete requests.
	rmdelsubj := mqttJSARepliesPrefix + "*." + mqttJSARetainedMsgDel
	if err := as.createSubscription(rmdelsubj, as.processRetainedMsgDel, &sid, &subs); err != nil {
		return nil, err
	}

	// No more creation of subscriptions past this point otherwise RACEs may happen.

	// Start the go routine that will send JS API requests.
	s.startGoRoutine(func() {
		defer s.grWG.Done()
		as.sendJSAPIrequests(s, c, accName, closeCh)
	})

	// Start the go routine that will clean up cached retained messages that expired.
	s.startGoRoutine(func() {
		defer s.grWG.Done()
		as.cleanupRetainedMessageCache(s, closeCh)
	})

	lookupStream := func(stream, txt string) (*StreamInfo, error) {
		si, err := jsa.lookupStream(stream)
		if err != nil {
			if IsNatsErr(err, JSStreamNotFoundErr) {
				return nil, nil
			}
			return nil, fmt.Errorf("lookup %s stream for account %q: %v", txt, accName, err)
		}
		if opts.MQTT.StreamReplicas == 0 {
			return si, nil
		}
		sr := 1
		if si.Cluster != nil {
			sr += len(si.Cluster.Replicas)
		}
		if replicas != sr {
			s.Warnf("MQTT %s stream replicas mismatch: current is %v but configuration is %v for '%s > %s'",
				txt, sr, replicas, accName, stream)
		}
		return si, nil
	}

	if si, err := lookupStream(mqttSessStreamName, "sessions"); err != nil {
		return nil, err
	} else if si == nil {
		// Create the stream for the sessions.
		cfg := &StreamConfig{
			Name:       mqttSessStreamName,
			Subjects:   []string{mqttSessStreamSubjectPrefix + as.domainTk + ">"},
			Storage:    FileStorage,
			Retention:  LimitsPolicy,
			Replicas:   replicas,
			MaxMsgsPer: 1,
		}
		if _, created, err := jsa.createStream(cfg); err == nil && created {
			as.transferUniqueSessStreamsToMuxed(s)
		} else if isErrorOtherThan(err, JSStreamNameExistErr) {
			return nil, fmt.Errorf("create sessions stream for account %q: %v", accName, err)
		}
	}

	msi, err := lookupStream(mqttStreamName, "messages")
	if err != nil {
		return nil, err
	}
	if msi == nil {
		// Create the stream for the messages.
		cfg := &StreamConfig{
			Name:      mqttStreamName,
			Subjects:  []string{mqttStreamSubjectPrefix + ">"},
			Storage:   FileStorage,
			Retention: InterestPolicy,
			Replicas:  replicas,
			// Honor MQTT 5.0 Message Expiry Interval: a stored PUBLISH carries a
			// per-message Nats-TTL so JetStream drops it once its lifetime has
			// elapsed, even if never delivered. Spec5 [3.3.2.3.3].
			AllowMsgTTL: true,
		}
		if _, _, cerr := jsa.createStream(cfg); cerr != nil {
			if isErrorOtherThan(cerr, JSStreamNameExistErr) {
				return nil, fmt.Errorf("create messages stream for account %q: %v", accName, cerr)
			}
			// Lost a creation race: re-check what the winner created, it may
			// be an older stream without per-message TTL.
			if msi, err = lookupStream(mqttStreamName, "messages"); err != nil {
				return nil, err
			}
		}
	}
	if msi != nil && !msi.Config.AllowMsgTTL {
		// Enable per-message TTL on a messages stream created before MQTT 5.0
		// message expiry support was added, so expiry is honored after upgrade.
		// Degrade rather than fail: without it MQTT still works, only v5
		// message expiry of stored messages is not enforced (e.g. while other
		// servers in a mixed-version cluster do not understand AllowMsgTTL).
		msi.Config.AllowMsgTTL = true
		if _, err := jsa.updateStream(&msi.Config); err != nil {
			msi.Config.AllowMsgTTL = false
			as.msgsStreamNoTTL = true
			s.Warnf("MQTT: unable to enable per-message TTL on messages stream for account %q, v5 Message Expiry of stored messages will not be enforced: %v", accName, err)
		}
	}

	if si, err := lookupStream(mqttQoS2IncomingMsgsStreamName, "QoS2 incoming messages"); err != nil {
		return nil, err
	} else if si == nil {
		// Create the stream for the incoming QoS2 messages that have not been
		// PUBREL-ed by the sender. Subject is
		// "$MQTT.qos2.<session>.<PI>", the .PI is to achieve exactly
		// once for each PI.
		cfg := &StreamConfig{
			Name:          mqttQoS2IncomingMsgsStreamName,
			Subjects:      []string{mqttQoS2IncomingMsgsStreamSubjectPrefix + ">"},
			Storage:       FileStorage,
			Retention:     LimitsPolicy,
			Discard:       DiscardNew,
			MaxMsgsPer:    1,
			DiscardNewPer: true,
			Replicas:      replicas,
		}
		if _, _, err := jsa.createStream(cfg); isErrorOtherThan(err, JSStreamNameExistErr) {
			return nil, fmt.Errorf("create QoS2 incoming messages stream for account %q: %v", accName, err)
		}
	}

	if si, err := lookupStream(mqttOutStreamName, "QoS2 outgoing PUBREL"); err != nil {
		return nil, err
	} else if si == nil {
		// Create the stream for the incoming QoS2 messages that have not been
		// PUBREL-ed by the sender. NATS messages are submitted as
		// "$MQTT.pubrel.<session hash>"
		cfg := &StreamConfig{
			Name:      mqttOutStreamName,
			Subjects:  []string{mqttOutSubjectPrefix + ">"},
			Storage:   FileStorage,
			Retention: InterestPolicy,
			Replicas:  replicas,
		}
		if _, _, err := jsa.createStream(cfg); isErrorOtherThan(err, JSStreamNameExistErr) {
			return nil, fmt.Errorf("create QoS2 outgoing PUBREL stream for account %q: %v", accName, err)
		}
	}

	// This is the only case where we need "si" after lookup/create
	needToTransfer := true
	si, err := lookupStream(mqttRetainedMsgsStreamName, "retained messages")
	switch {
	case err != nil:
		return nil, err

	case si == nil:
		// Create the stream for retained messages.
		cfg := &StreamConfig{
			Name:       mqttRetainedMsgsStreamName,
			Subjects:   []string{mqttRetainedMsgsStreamSubject + ">"},
			Storage:    FileStorage,
			Retention:  LimitsPolicy,
			Replicas:   replicas,
			MaxMsgsPer: 1,
			// Honor MQTT 5.0 Message Expiry Interval for retained messages via a
			// per-message Nats-TTL. Spec5 [3.3.2.3.3].
			AllowMsgTTL: true,
		}
		// We will need "si" outside of this block.
		si, _, err = jsa.createStream(cfg)
		if err != nil {
			if isErrorOtherThan(err, JSStreamNameExistErr) {
				return nil, fmt.Errorf("create retained messages stream for account %q: %v", accName, err)
			}
			// Suppose we had a race and the stream was actually created by another
			// node, we really need "si" after that, so lookup the stream again here.
			si, err = lookupStream(mqttRetainedMsgsStreamName, "retained messages")
			if err != nil {
				return nil, err
			}
		}
		needToTransfer = false

	default:
		needToTransfer = si.Config.MaxMsgsPer != 1
	}

	// Doing this check outside of above if/else due to possible race when
	// creating the stream.
	wantedSubj := mqttRetainedMsgsStreamSubject + ">"
	if len(si.Config.Subjects) != 1 || si.Config.Subjects[0] != wantedSubj {
		// Update only the Subjects at this stage, not MaxMsgsPer yet.
		si.Config.Subjects = []string{wantedSubj}
		if si, err = jsa.updateStream(&si.Config); err != nil {
			return nil, fmt.Errorf("failed to update stream config: %w", err)
		}
	}

	transferRMS := func() error {
		if !needToTransfer {
			return nil
		}

		as.transferRetainedToPerKeySubjectStream(s)

		// We need another lookup to have up-to-date si.State values in order
		// to load all retained messages.
		si, err = lookupStream(mqttRetainedMsgsStreamName, "retained messages")
		if err != nil {
			return err
		}
		needToTransfer = false
		return nil
	}

	// Attempt to transfer all "single subject" retained messages to new
	// subjects. It may fail, will log its own error; ignore it the first time
	// and proceed to updating MaxMsgsPer. Then we invoke transferRMS() again,
	// which will get another chance to resolve the error; if not we bail there.
	if err = transferRMS(); err != nil {
		return nil, err
	}

	// Now, if the stream does not have MaxMsgsPer set to 1, and there are no
	// more messages on the single $MQTT.rmsgs subject, update the stream again.
	if si.Config.MaxMsgsPer != 1 {
		si.Config.MaxMsgsPer = 1
		// We will need an up-to-date si, so don't use local variable here.
		if si, err = jsa.updateStream(&si.Config); err != nil {
			return nil, fmt.Errorf("failed to update stream config: %w", err)
		}
	}

	// Enable per-message TTL on a retained messages stream created before MQTT
	// 5.0 message expiry support was added, so expiry is honored after upgrade.
	// Degrade rather than fail (see the messages stream above); expired
	// retained messages are still withheld from delivery, only their stored
	// copies are not reaped.
	if !si.Config.AllowMsgTTL {
		si.Config.AllowMsgTTL = true
		if nsi, err := jsa.updateStream(&si.Config); err != nil {
			si.Config.AllowMsgTTL = false
			as.rmsgsStreamNoTTL = true
			s.Warnf("MQTT: unable to enable per-message TTL on retained messages stream for account %q, expired retained messages will not be reaped from storage: %v", accName, err)
		} else {
			si = nsi
		}
	}

	// If we failed the first time, there is now at most one lingering message
	// in the old subject. Try again (it will be a NO-OP if succeeded the first
	// time).
	if err = transferRMS(); err != nil {
		return nil, err
	}

	// Opportunistically delete the old (legacy) consumer, from v2.10.10 and
	// before. Ignore any errors that might arise.
	rmLegacyDurName := mqttRetainedMsgsStreamName + "_" + jsa.id
	jsa.deleteConsumer(mqttRetainedMsgsStreamName, rmLegacyDurName, true)

	// Create a new, uniquely names consumer for retained messages for this
	// server. The prior one will expire eventually.
	ccfg := &CreateConsumerRequest{
		Stream: mqttRetainedMsgsStreamName,
		Config: ConsumerConfig{
			Name:              mqttRetainedMsgsStreamName + "_" + nuid.Next(),
			FilterSubject:     mqttRetainedMsgsStreamSubject + ">",
			DeliverSubject:    rmsubj,
			ReplayPolicy:      ReplayInstant,
			AckPolicy:         AckNone,
			InactiveThreshold: 5 * time.Minute,
		},
	}
	if _, err := jsa.createEphemeralConsumer(ccfg); err != nil {
		return nil, fmt.Errorf("create retained messages consumer for account %q: %v", accName, err)
	}

	// Set this so that on defer we don't cleanup.
	success = true

	return as, nil
}

func (s *Server) mqttDetermineReplicas() int {
	// If not clustered, then replica will be 1.
	if !s.JetStreamIsClustered() {
		return 1
	}
	opts := s.getOpts()
	replicas := 0
	for _, u := range opts.Routes {
		host := u.Hostname()
		// If this is an IP just add one.
		if net.ParseIP(host) != nil {
			replicas++
		} else {
			addrs, _ := net.LookupHost(host)
			replicas += len(addrs)
		}
	}
	if replicas < 1 {
		replicas = 1
	} else if replicas > 3 {
		replicas = 3
	}
	return replicas
}

//////////////////////////////////////////////////////////////////////////////
//
// JS APIs related functions
//
//////////////////////////////////////////////////////////////////////////////

func (jsa *mqttJSA) newRequest(kind, subject string, hdr int, msg []byte) (any, error) {
	return jsa.newRequestEx(kind, subject, _EMPTY_, hdr, msg)
}

func (jsa *mqttJSA) prefixDomain(subject string) string {
	if jsa.domain != _EMPTY_ {
		// rewrite js api prefix with domain
		if sub := strings.TrimPrefix(subject, JSApiPrefix+"."); sub != subject {
			subject = fmt.Sprintf("$JS.%s.API.%s", jsa.domain, sub)
		}
	}
	return subject
}

func (jsa *mqttJSA) newRequestEx(kind, subject, cidHash string, hdr int, msg []byte) (any, error) {
	responses, err := jsa.newRequestExMulti(kind, subject, cidHash, []int{hdr}, [][]byte{msg})
	if err != nil {
		return nil, err
	}
	if len(responses) != 1 {
		return nil, fmt.Errorf("unreachable: invalid number of responses (%d)", len(responses))
	}
	return responses[0].value, nil
}

// newRequestExMulti sends multiple messages on the same subject and waits for
// all responses. It returns the same number of responses in the same order as
// msgs parameter. In case of a timeout it returns an error as well as all
// responses received as a sparsely populated array, matching msgs, with nils
// for the values that have not yet been received.
//
// Note that each response may represent an error and should be inspected as
// such by the caller.
func (jsa *mqttJSA) newRequestExMulti(kind, subject, cidHash string, hdrs []int, msgs [][]byte) ([]*mqttJSAResponse, error) {
	if len(hdrs) != len(msgs) {
		return nil, fmt.Errorf("unreachable: invalid number of messages (%d) or header offsets (%d)", len(msgs), len(hdrs))
	}
	responseCh := make(chan *mqttJSAResponse, len(msgs))

	// Generate and queue all outgoing requests, have all results reported to
	// responseCh, and store a map of reply subjects to the original subjects'
	// indices.
	r2i := map[string]int{}
	for i, msg := range msgs {
		hdr := hdrs[i]
		var sb strings.Builder
		// Either we use nuid.Next() which uses a global lock, or our own nuid object, but
		// then it needs to be "write" protected. This approach will reduce across account
		// contention since we won't use the global nuid's lock.
		jsa.mu.Lock()
		uid := jsa.nuid.Next()
		sb.WriteString(jsa.rplyr)
		jsa.mu.Unlock()

		sb.WriteString(kind)
		sb.WriteByte(btsep)
		if cidHash != _EMPTY_ {
			sb.WriteString(cidHash)
			sb.WriteByte(btsep)
		}
		sb.WriteString(uid)
		reply := sb.String()

		// Add responseCh to the reply channel map. It will be cleaned out on
		// timeout (see below), or in processJSAPIReplies upon receiving the
		// response.
		jsa.replies.Store(reply, responseCh)

		subject = jsa.prefixDomain(subject)
		jsa.sendq.push(&mqttJSPubMsg{
			subj:  subject,
			reply: reply,
			hdr:   hdr,
			msg:   msg,
		})
		r2i[reply] = i
	}

	// Wait for all responses to come back, or for the timeout to expire. We
	// don't want to use time.After() which causes memory growth because the
	// timer can't be stopped and will need to expire to then be garbage
	// collected.
	c := 0
	responses := make([]*mqttJSAResponse, len(msgs))
	start := time.Now()
	t := time.NewTimer(jsa.timeout)
	defer t.Stop()
	for {
		select {
		case r := <-responseCh:
			i := r2i[r.reply]
			responses[i] = r
			c++
			if c == len(msgs) {
				return responses, nil
			}

		case <-jsa.quitCh:
			return nil, ErrServerNotRunning

		case <-t.C:
			var reply string
			now := time.Now()
			for reply = range r2i { // preserve the last value for Errorf
				jsa.replies.Delete(reply)
			}

			if len(msgs) == 1 {
				return responses, fmt.Errorf("timeout after %v: request type %q on %q (reply=%q)", now.Sub(start), kind, subject, reply)
			} else {
				return responses, fmt.Errorf("timeout after %v: request type %q on %q: got %d out of %d", now.Sub(start), kind, subject, c, len(msgs))
			}
		}
	}
}

func (jsa *mqttJSA) sendAck(ackSubject string) {
	// Send to the ack subject with no payload.
	jsa.sendMsg(ackSubject, nil)
}

func (jsa *mqttJSA) sendMsg(subj string, msg []byte) {
	if subj == _EMPTY_ {
		return
	}
	// We pass -1 for the hdr so that the send loop does not need to
	// add the "client info" header. This is not a JS API request per se.
	jsa.sendq.push(&mqttJSPubMsg{subj: subj, msg: msg, hdr: -1})
}

func (jsa *mqttJSA) createEphemeralConsumer(cfg *CreateConsumerRequest) (*JSApiConsumerCreateResponse, error) {
	cfgb, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	subj := fmt.Sprintf(JSApiConsumerCreateT, cfg.Stream)
	ccri, err := jsa.newRequest(mqttJSAConsumerCreate, subj, 0, cfgb)
	if err != nil {
		return nil, err
	}
	ccr := ccri.(*JSApiConsumerCreateResponse)
	return ccr, ccr.ToError()
}

func (jsa *mqttJSA) createDurableConsumer(cfg *CreateConsumerRequest) (*JSApiConsumerCreateResponse, error) {
	cfgb, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	subj := fmt.Sprintf(JSApiDurableCreateT, cfg.Stream, cfg.Config.Durable)
	ccri, err := jsa.newRequest(mqttJSAConsumerCreate, subj, 0, cfgb)
	if err != nil {
		return nil, err
	}
	ccr := ccri.(*JSApiConsumerCreateResponse)
	return ccr, ccr.ToError()
}

// if noWait is specified, does not wait for the JS response, returns nil
func (jsa *mqttJSA) deleteConsumer(streamName, consName string, noWait bool) (*JSApiConsumerDeleteResponse, error) {
	subj := fmt.Sprintf(JSApiConsumerDeleteT, streamName, consName)
	if noWait {
		jsa.sendMsg(subj, nil)
		return nil, nil
	}

	cdri, err := jsa.newRequest(mqttJSAConsumerDel, subj, 0, nil)
	if err != nil {
		return nil, err
	}
	cdr := cdri.(*JSApiConsumerDeleteResponse)
	return cdr, cdr.ToError()
}

func (jsa *mqttJSA) createStream(cfg *StreamConfig) (*StreamInfo, bool, error) {
	cfgb, err := json.Marshal(cfg)
	if err != nil {
		return nil, false, err
	}
	scri, err := jsa.newRequest(mqttJSAStreamCreate, fmt.Sprintf(JSApiStreamCreateT, cfg.Name), 0, cfgb)
	if err != nil {
		return nil, false, err
	}
	scr := scri.(*JSApiStreamCreateResponse)
	return scr.StreamInfo, scr.DidCreate, scr.ToError()
}

func (jsa *mqttJSA) updateStream(cfg *StreamConfig) (*StreamInfo, error) {
	cfgb, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	scri, err := jsa.newRequest(mqttJSAStreamUpdate, fmt.Sprintf(JSApiStreamUpdateT, cfg.Name), 0, cfgb)
	if err != nil {
		return nil, err
	}
	scr := scri.(*JSApiStreamUpdateResponse)
	return scr.StreamInfo, scr.ToError()
}

func (jsa *mqttJSA) lookupStream(name string) (*StreamInfo, error) {
	slri, err := jsa.newRequest(mqttJSAStreamLookup, fmt.Sprintf(JSApiStreamInfoT, name), 0, nil)
	if err != nil {
		return nil, err
	}
	slr := slri.(*JSApiStreamInfoResponse)
	return slr.StreamInfo, slr.ToError()
}

func (jsa *mqttJSA) deleteStream(name string) (bool, error) {
	sdri, err := jsa.newRequest(mqttJSAStreamDel, fmt.Sprintf(JSApiStreamDeleteT, name), 0, nil)
	if err != nil {
		return false, err
	}
	sdr := sdri.(*JSApiStreamDeleteResponse)
	return sdr.Success, sdr.ToError()
}

func (jsa *mqttJSA) loadLastMsgFor(streamName string, subject string) (*StoredMsg, error) {
	mreq := &JSApiMsgGetRequest{LastFor: subject}
	req, err := json.Marshal(mreq)
	if err != nil {
		return nil, err
	}
	lmri, err := jsa.newRequest(mqttJSAMsgLoad, fmt.Sprintf(JSApiMsgGetT, streamName), 0, req)
	if err != nil {
		return nil, err
	}
	lmr := lmri.(*JSApiMsgGetResponse)
	return lmr.Message, lmr.ToError()
}

func (jsa *mqttJSA) loadLastMsgForMulti(streamName string, subjects []string) ([]*JSApiMsgGetResponse, error) {
	marshaled := make([][]byte, 0, len(subjects))
	headerBytes := make([]int, 0, len(subjects))
	for _, subject := range subjects {
		mreq := &JSApiMsgGetRequest{LastFor: subject}
		bb, err := json.Marshal(mreq)
		if err != nil {
			return nil, err
		}
		marshaled = append(marshaled, bb)
		headerBytes = append(headerBytes, 0)
	}

	all, err := jsa.newRequestExMulti(mqttJSAMsgLoad, fmt.Sprintf(JSApiMsgGetT, streamName), _EMPTY_, headerBytes, marshaled)
	// all has the same order as subjects, preserve it as we unmarshal
	responses := make([]*JSApiMsgGetResponse, len(all))
	for i, v := range all {
		if v != nil {
			responses[i] = v.value.(*JSApiMsgGetResponse)
		}
	}
	return responses, err
}

func (jsa *mqttJSA) loadNextMsgFor(streamName string, subject string) (*StoredMsg, error) {
	mreq := &JSApiMsgGetRequest{NextFor: subject}
	req, err := json.Marshal(mreq)
	if err != nil {
		return nil, err
	}
	lmri, err := jsa.newRequest(mqttJSAMsgLoad, fmt.Sprintf(JSApiMsgGetT, streamName), 0, req)
	if err != nil {
		return nil, err
	}
	lmr := lmri.(*JSApiMsgGetResponse)
	return lmr.Message, lmr.ToError()
}

func (jsa *mqttJSA) loadMsg(streamName string, seq uint64) (*StoredMsg, error) {
	mreq := &JSApiMsgGetRequest{Seq: seq}
	req, err := json.Marshal(mreq)
	if err != nil {
		return nil, err
	}
	lmri, err := jsa.newRequest(mqttJSAMsgLoad, fmt.Sprintf(JSApiMsgGetT, streamName), 0, req)
	if err != nil {
		return nil, err
	}
	lmr := lmri.(*JSApiMsgGetResponse)
	return lmr.Message, lmr.ToError()
}

func (jsa *mqttJSA) storeMsgNoWait(subject string, hdrLen int, msg []byte) {
	jsa.sendq.push(&mqttJSPubMsg{
		subj: subject,
		msg:  msg,
		hdr:  hdrLen,
	})
}

func (jsa *mqttJSA) storeMsg(subject string, headers int, msg []byte) (*JSPubAckResponse, error) {
	smri, err := jsa.newRequest(mqttJSAMsgStore, subject, headers, msg)
	if err != nil {
		return nil, err
	}
	smr := smri.(*JSPubAckResponse)
	return smr, smr.ToError()
}

func (jsa *mqttJSA) storeSessionMsg(domainTk, cidHash string, hdr int, msg []byte) (*JSPubAckResponse, error) {
	// Compute subject where the session is being stored
	subject := mqttSessStreamSubjectPrefix + domainTk + cidHash

	// Passing cidHash will add it to the JS reply subject, so that we can use
	// it in processSessionPersist.
	smri, err := jsa.newRequestEx(mqttJSASessPersist, subject, cidHash, hdr, msg)
	if err != nil {
		return nil, err
	}
	smr := smri.(*JSPubAckResponse)
	return smr, smr.ToError()
}

func (jsa *mqttJSA) loadSessionMsg(domainTk, cidHash string) (*StoredMsg, error) {
	subject := mqttSessStreamSubjectPrefix + domainTk + cidHash
	return jsa.loadLastMsgFor(mqttSessStreamName, subject)
}

func (jsa *mqttJSA) deleteMsg(stream string, seq uint64, wait bool) error {
	dreq := JSApiMsgDeleteRequest{Seq: seq, NoErase: true}
	req, _ := json.Marshal(dreq)
	subj := jsa.prefixDomain(fmt.Sprintf(JSApiMsgDeleteT, stream))
	if !wait {
		jsa.sendq.push(&mqttJSPubMsg{
			subj: subj,
			msg:  req,
		})
		return nil
	}
	dmi, err := jsa.newRequest(mqttJSAMsgDelete, subj, 0, req)
	if err != nil {
		return err
	}
	dm := dmi.(*JSApiMsgDeleteResponse)
	return dm.ToError()
}

//////////////////////////////////////////////////////////////////////////////
//
// Account Sessions Manager related functions
//
//////////////////////////////////////////////////////////////////////////////

// Returns true if `err` is not nil and does not match the api error with ErrorIdentifier id
func isErrorOtherThan(err error, id ErrorIdentifier) bool {
	return err != nil && !IsNatsErr(err, id)
}

// Process JS API replies.
//
// Can run from various go routines (consumer's loop, system send loop, etc..).
func (as *mqttAccountSessionManager) processJSAPIReplies(_ *subscription, pc *client, _ *Account, subject, _ string, msg []byte) {
	token := tokenAt(subject, mqttJSATokenPos)
	if token == _EMPTY_ {
		return
	}
	jsa := &as.jsa
	chi, ok := jsa.replies.Load(subject)
	if !ok {
		return
	}
	jsa.replies.Delete(subject)
	ch := chi.(chan *mqttJSAResponse)
	out := func(value any) {
		ch <- &mqttJSAResponse{reply: subject, value: value}
	}
	switch token {
	case mqttJSAStreamCreate:
		var resp = &JSApiStreamCreateResponse{}
		if err := json.Unmarshal(msg, resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	case mqttJSAStreamUpdate:
		var resp = &JSApiStreamUpdateResponse{}
		if err := json.Unmarshal(msg, resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	case mqttJSAStreamLookup:
		var resp = &JSApiStreamInfoResponse{}
		if err := json.Unmarshal(msg, &resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	case mqttJSAStreamDel:
		var resp = &JSApiStreamDeleteResponse{}
		if err := json.Unmarshal(msg, &resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	case mqttJSAConsumerCreate:
		var resp = &JSApiConsumerCreateResponse{}
		if err := json.Unmarshal(msg, resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	case mqttJSAConsumerDel:
		var resp = &JSApiConsumerDeleteResponse{}
		if err := json.Unmarshal(msg, resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	case mqttJSAMsgStore, mqttJSASessPersist:
		var resp = &JSPubAckResponse{}
		if err := json.Unmarshal(msg, resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	case mqttJSAMsgLoad:
		var resp = &JSApiMsgGetResponse{}
		if err := json.Unmarshal(msg, &resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	case mqttJSAStreamNames:
		var resp = &JSApiStreamNamesResponse{}
		if err := json.Unmarshal(msg, resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	case mqttJSAMsgDelete:
		var resp = &JSApiMsgDeleteResponse{}
		if err := json.Unmarshal(msg, resp); err != nil {
			resp.Error = NewJSInvalidJSONError(err)
		}
		out(resp)
	default:
		pc.Warnf("Unknown reply code %q", token)
	}
}

// This will both load all retained messages and process updates from the cluster.
//
// Run from various go routines (JS consumer, etc..).
// No lock held on entry.
func (as *mqttAccountSessionManager) processRetainedMsg(_ *subscription, c *client, _ *Account, subject, reply string, rmsg []byte) {
	h, m := c.msgParts(rmsg)
	// We need to strip the trailing "\r\n".
	if l := len(m); l >= LEN_CR_LF {
		m = m[:l-LEN_CR_LF]
	}
	rm, err := mqttDecodeRetainedMessage(subject, h, m)
	if err != nil {
		return
	}
	if strings.IndexByte(rm.Subject, 0x7f) >= 0 {
		c.Warnf("Skipping retained message for subject %q: unsupported character 0x7f", rm.Subject)
		return
	}
	// The as.jsa.id is immutable, so no need to have a rlock here.
	local := rm.Origin == as.jsa.id
	// Get the stream sequence for this message.
	seq, _, _, _, _ := ackReplyInfo(reply)
	if len(m) == 0 {
		// An empty payload means that we need to remove the retained message.
		rmSeq := as.removeRetainedMsg(rm.Subject, 0)
		if local {
			if rmSeq > 0 {
				// This is for backward compatibility reasons.
				// Should be removed in a future release.
				as.notifyRetainedMsgDeleted(rm.Subject, rmSeq)
			}
			// Delete this very message we just processed, we don't need it anymore.
			as.deleteRetainedMsg(seq)
		}
	} else {
		// Add this retained message. The `rm.Msg` references some buffer that we
		// don't own. But addRetainedMsg() will take care of making a copy of
		// `rm.Msg` it `rm` ends-up being stored in the cache.
		as.addRetainedMsg(rm.Subject, seq, rm)
	}
}

// NOTE: This is maintained for backward compatibility reasons. Should be removed in 2.14/2.15?
func (as *mqttAccountSessionManager) processRetainedMsgDel(_ *subscription, c *client, _ *Account, subject, reply string, rmsg []byte) {
	idHash := tokenAt(subject, 3)
	if idHash == _EMPTY_ || idHash == as.jsa.id {
		return
	}
	_, msg := c.msgParts(rmsg)
	if len(msg) < LEN_CR_LF {
		return
	}
	var drm mqttRetMsgDel
	if err := json.Unmarshal(msg, &drm); err != nil {
		return
	}
	as.removeRetainedMsg(drm.Subject, drm.Seq)
}

// This will receive all JS API replies for a request to store a session record,
// including the reply for our own server, which we will ignore.
// This allows us to detect that some application somewhere else in the cluster
// is connecting with the same client ID, and therefore we need to close the
// connection that is currently using this client ID.
//
// Can run from various go routines (system send loop, etc..).
// No lock held on entry.
func (as *mqttAccountSessionManager) processSessionPersist(_ *subscription, pc *client, _ *Account, subject, _ string, rmsg []byte) {
	// Ignore our own responses here (they are handled elsewhere)
	if tokenAt(subject, mqttJSAIdTokenPos) == as.jsa.id {
		return
	}
	cIDHash := tokenAt(subject, mqttJSAClientIDPos)
	_, msg := pc.msgParts(rmsg)
	if len(msg) < LEN_CR_LF {
		return
	}
	var par = &JSPubAckResponse{}
	if err := json.Unmarshal(msg, par); err != nil {
		return
	}
	if err := par.Error; err != nil {
		return
	}
	as.mu.RLock()
	// Note that as.domainTk includes a terminal '.', so strip to compare to PubAck.Domain.
	dl := len(as.domainTk)
	if dl > 0 {
		dl--
	}
	ignore := par.Domain != as.domainTk[:dl]
	as.mu.RUnlock()
	if ignore {
		return
	}

	as.mu.Lock()
	defer as.mu.Unlock()
	sess, ok := as.sessByHash[cIDHash]
	if !ok {
		return
	}
	// If our current session's stream sequence is higher, it means that this
	// update is stale, so we don't do anything here.
	sess.mu.Lock()
	ignore = par.Sequence < sess.seq
	sess.mu.Unlock()
	if ignore {
		return
	}
	as.removeSession(sess, false)
	sess.mu.Lock()
	ec := sess.c
	if ec != nil {
		as.addSessToFlappers(sess.id)
		ec.Warnf("Closing because a remote connection has started with the same client ID: %q", sess.id)
		// Disassociate the client from the session so that on client close,
		// nothing will be done with regards to cleaning up the session,
		// such as deleting stream, etc..
		sess.c = nil
	}
	sess.mu.Unlock()
	if ec != nil {
		// Tell the evicted v5 client why before the close (no-op for 3.1.1);
		// enqueued outside sess.mu since it takes the client lock. Spec5 [3.1.4].
		ec.mqttEnqueueDisconnect(mqttReasonSessionTakenOver)
		// Remove in separate go routine.
		go ec.closeConnection(DuplicateClientID)
	}
}

// Adds this client ID to the flappers map, and if needed start the timer
// for map cleanup.
//
// Lock held on entry.
func (as *mqttAccountSessionManager) addSessToFlappers(clientID string) {
	as.flappers[clientID] = time.Now()
	if as.flapTimer == nil {
		as.flapTimer = time.AfterFunc(mqttFlapCleanItvl, func() {
			as.mu.Lock()
			defer as.mu.Unlock()
			// In case of shutdown, this will be nil
			if as.flapTimer == nil {
				return
			}
			now := time.Now()
			for cID, tm := range as.flappers {
				if now.Sub(tm) > mqttSessJailDur {
					delete(as.flappers, cID)
				}
			}
			as.flapTimer.Reset(mqttFlapCleanItvl)
		})
	}
}

// Remove this client ID from the flappers map.
//
// Lock held on entry.
func (as *mqttAccountSessionManager) removeSessFromFlappers(clientID string) {
	delete(as.flappers, clientID)
	// Do not stop/set timer to nil here. Better leave the timer run at its
	// regular interval and detect that there is nothing to do. The timer
	// will be stopped on shutdown.
}

// Helper to create a subscription. It updates the sid and array of subscriptions.
func (as *mqttAccountSessionManager) createSubscription(subject string, cb msgHandler, sid *int64, subs *[]*subscription) error {
	sub, err := as.jsa.c.processSub([]byte(subject), nil, []byte(strconv.FormatInt(*sid, 10)), cb, false)
	if err != nil {
		return err
	}
	*sid++
	*subs = append(*subs, sub)
	return nil
}

// A timer loop to cleanup up expired cached retained messages for a given MQTT account.
// The closeCh is used by the caller to be able to interrupt this routine
// if the rest of the initialization fails, since the quitCh is really
// only used when the server shutdown.
//
// No lock held on entry.
func (as *mqttAccountSessionManager) cleanupRetainedMessageCache(s *Server, closeCh chan struct{}) {
	tt := time.NewTicker(mqttRetainedCacheTTL)
	defer tt.Stop()
	for {
		select {
		case <-tt.C:
			// Set a limit to the number of retained messages to scan since we
			// lock as for it. Since the map enumeration gives random order we
			// should eventually clean up everything.
			i, maxScan := 0, 10*1000
			now := time.Now()
			as.rmsCache.Range(func(key, value any) bool {
				rm := value.(*mqttRetainedMsg)
				// Evict when the cache entry aged out, or when the message
				// itself reached its MQTT 5.0 Message Expiry deadline (its
				// stored copy is TTL-reaped by JetStream at the same time).
				if now.After(rm.expiresFromCache) ||
					(!rm.expires.IsZero() && now.After(rm.expires)) {
					as.rmsCache.Delete(key)
				}
				i++
				return i < maxScan
			})

		case <-closeCh:
			return
		case <-s.quitCh:
			return
		}
	}
}

// Loop to send JS API requests for a given MQTT account.
// The closeCh is used by the caller to be able to interrupt this routine
// if the rest of the initialization fails, since the quitCh is really
// only used when the server shutdown.
//
// No lock held on entry.
func (as *mqttAccountSessionManager) sendJSAPIrequests(s *Server, c *client, accName string, closeCh chan struct{}) {
	var cluster string
	if s.JetStreamEnabled() && !as.jsa.domainSet {
		// Only request the own cluster when it is clear that
		cluster = s.cachedClusterName()
	}
	as.mu.RLock()
	sendq := as.jsa.sendq
	quitCh := as.jsa.quitCh
	ci := ClientInfo{Account: accName, Cluster: cluster}
	acc := c.acc
	as.mu.RUnlock()

	// The account session manager does not have a suhtdown API per-se, instead,
	// we will cleanup things when this go routine exits after detecting that the
	// server is shutdown or the initialization of the account manager failed.
	defer func() {
		as.mu.Lock()
		if as.flapTimer != nil {
			as.flapTimer.Stop()
			as.flapTimer = nil
		}
		as.mu.Unlock()
	}()

	b, _ := json.Marshal(ci)
	hdrStart := bytes.Buffer{}
	hdrStart.WriteString(hdrLine)
	http.Header{ClientInfoHdr: []string{string(b)}}.Write(&hdrStart)
	hdrStart.WriteString(CR_LF)
	hdrStart.WriteString(CR_LF)
	hdrb := hdrStart.Bytes()

	for {
		select {
		case <-sendq.ch:
			pmis := sendq.pop()
			for _, r := range pmis {
				var nsize int

				msg := r.msg
				// If r.hdr is set to -1, it means that there is no need for any header.
				if r.hdr != -1 {
					bb := bytes.Buffer{}
					if r.hdr > 0 {
						// This means that the header has been set by the caller and is
						// already part of `msg`, so simply set c.pa.hdr to the given value.
						c.pa.hdr = r.hdr
						nsize = len(msg)
						msg = append(msg, _CRLF_...)
					} else {
						// We need the ClientInfo header, so add it here.
						bb.Write(hdrb)
						c.pa.hdr = bb.Len()
						bb.Write(r.msg)
						nsize = bb.Len()
						bb.WriteString(_CRLF_)
						msg = bb.Bytes()
					}
					c.pa.hdb = []byte(strconv.Itoa(c.pa.hdr))
				} else {
					c.pa.hdr = -1
					c.pa.hdb = nil
					nsize = len(msg)
					msg = append(msg, _CRLF_...)
				}

				c.pa.subject = []byte(r.subj)
				c.pa.reply = []byte(r.reply)
				c.pa.size = nsize
				c.pa.szb = []byte(strconv.Itoa(nsize))
				c.pa.mapped = nil

				if acc.hasMappings() {
					if changed := c.selectMappedSubject(); changed {
						c.traceOutOp("MAPPINGS", fmt.Appendf(nil, "%s -> %s", c.pa.mapped, c.pa.subject))
					}
				}
				c.processInboundClientMsg(msg)
				c.flushClients(0)
			}
			sendq.recycle(&pmis)

		case <-closeCh:
			return
		case <-quitCh:
			return
		}
	}
}

// Add/Replace this message from the retained messages map.
// If a message for this topic already existed, the existing record is updated
// with the provided information.
// Lock not held on entry.
func (as *mqttAccountSessionManager) addRetainedMsg(key string, sseq uint64, rm *mqttRetainedMsg) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.retmsgs == nil {
		as.retmsgs = stree.NewSubjectTree[mqttRetainedMsgRef]()
	} else {
		// Check if we already had one retained message. If so, update the existing one.
		if erf, exists := as.retmsgs.Find(stringToBytes(key)); exists {
			// Update the stream sequence with the new value.
			erf.sseq = sseq
			// Update the in-memory retained message cache but only for messages
			// that are already in the cache, i.e. have been (recently) used.
			// If that is the case, we ask setCachedRetainedMsg() to make a copy
			// of rm.Msg bytes slice.
			as.setCachedRetainedMsg(key, rm, true, true)
			return
		}
	}
	as.retmsgs.Insert([]byte(key), mqttRetainedMsgRef{sseq: sseq})
}

// Remove the retained message stored with the `subject` key from the map/cache.
// When invoked from the retained message stream's consumer, this function will
// be called with `seq == 0`, this is because add/remove are serialized in this
// stream and so the request is to remove the current retained message.
// But in some conditions, we will invoke this function from some other places
// with `seq > 0` which means that the retained message will be removed only if
// its sequence is the same than the provided one.
// This function returns the sequence associated with the existing retained
// message that is being removed (used with `seq == 0`) and returns 0 if the
// retained message was not removed from the map (not found or sequence did not
// match).
func (as *mqttAccountSessionManager) removeRetainedMsg(subject string, seq uint64) uint64 {
	as.mu.Lock()
	defer as.mu.Unlock()
	rm, ok := as.retmsgs.Find(stringToBytes(subject))
	if !ok || (seq > 0 && rm.sseq != seq) {
		return 0
	}
	rm, _ = as.retmsgs.Delete(stringToBytes(subject))
	as.rmsCache.Delete(subject)
	return rm.sseq
}

// First check if this session's client ID is already in the "locked" map,
// which if it is the case means that another client is now bound to this
// session and this should return an error.
// If not in the "locked" map, but the client is not bound with this session,
// then same error is returned.
// Finally, if all checks ok, then the session's ID is added to the "locked" map.
//
// No lock held on entry.
func (as *mqttAccountSessionManager) lockSession(sess *mqttSession, c *client) error {
	as.mu.Lock()
	defer as.mu.Unlock()
	var fail bool
	if _, fail = as.sessLocked[sess.id]; !fail {
		sess.mu.Lock()
		fail = sess.c != c
		sess.mu.Unlock()
	}
	if fail {
		return fmt.Errorf("another session is in use with client ID %q", sess.id)
	}
	as.sessLocked[sess.id] = struct{}{}
	return nil
}

// Remove the session from the "locked" map.
//
// No lock held on entry.
func (as *mqttAccountSessionManager) unlockSession(sess *mqttSession) {
	as.mu.Lock()
	delete(as.sessLocked, sess.id)
	as.mu.Unlock()
}

// Simply adds the session to the various sessions maps.
// The boolean `lock` indicates if this function should acquire the lock
// prior to adding to the maps.
//
// No lock held on entry.
func (as *mqttAccountSessionManager) addSession(sess *mqttSession, lock bool) {
	if lock {
		as.mu.Lock()
	}
	as.sessions[sess.id] = sess
	as.sessByHash[sess.idHash] = sess
	if lock {
		as.mu.Unlock()
	}
}

// Simply removes the session from the various sessions maps.
// The boolean `lock` indicates if this function should acquire the lock
// prior to removing from the maps.
//
// No lock held on entry.
func (as *mqttAccountSessionManager) removeSession(sess *mqttSession, lock bool) {
	if lock {
		as.mu.Lock()
	}
	delete(as.sessions, sess.id)
	delete(as.sessByHash, sess.idHash)
	if lock {
		as.mu.Unlock()
	}
}

// Helper to set the sub's mqtt fields and possibly serialize (pre-loaded)
// retained messages.
//
// Session lock held on entry. Acquires the subs lock and holds it for
// the duration. Non-MQTT messages coming into mqttDeliverMsgCbQoS0 will be
// waiting.
func (sess *mqttSession) processQOS12Sub(
	c *client, // subscribing client.
	subject, sid []byte, isReserved bool, qos byte, jsDurName string, h msgHandler, // subscription parameters.
) (*subscription, error) {
	return sess.processSub(c, subject, sid, isReserved, qos, jsDurName, h, false, nil, false, nil)
}

func (sess *mqttSession) processSub(
	c *client, // subscribing client.
	subject, sid []byte, isReserved bool, qos byte, jsDurName string, h msgHandler, // subscription parameters.
	initShadow bool, // do we need to scan for shadow subscriptions? (not for QOS1+)
	rms map[string]*mqttRetainedMsg, // preloaded rms (can be empty, or missing items if errors)
	trace bool, // trace serialized retained messages in the log?
	as *mqttAccountSessionManager, // needed only for rms serialization.
) (*subscription, error) {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		if elapsed > mqttProcessSubTooLong {
			c.Warnf("Took too long to process subscription for %q: %v", subject, elapsed)
		}
	}()

	// Hold subsMu to prevent QOS0 messages callback from doing anything until
	// the (MQTT) sub is initialized.
	sess.subsMu.Lock()
	defer sess.subsMu.Unlock()

	sub, err := c.processSub(subject, nil, sid, h, false)
	if err != nil {
		// c.processSub already called c.Errorf(), so no need here.
		return nil, err
	}
	subs := []*subscription{sub}
	if initShadow {
		subs = append(subs, sub.shadow...)
	}
	for _, ss := range subs {
		if ss.mqtt == nil {
			// reserved is set only once and once the subscription has been
			// created it can be considered immutable.
			ss.mqtt = &mqttSub{
				reserved: isReserved,
			}
		}
		// QOS and jsDurName can be changed on an existing subscription, so
		// accessing it later requires a lock.
		ss.mqtt.qos = qos
		ss.mqtt.jsDur = jsDurName
	}

	if len(rms) > 0 {
		// Only deal with retained messages for the normal subscription,
		// not the shadow one (which is for a different account and subject).
		as.serializeRetainedMsgsForSub(rms, sess, c, sub, trace)
	}

	return sub, nil
}

// Process subscriptions for the given session/client.
//
// When `fromSubProto` is false, it means that this is invoked from the CONNECT
// protocol, when restoring subscriptions that were saved for this session.
// In that case, there is no need to update the session record.
//
// When `fromSubProto` is true, it means that this call is invoked from the
// processing of the SUBSCRIBE protocol, which means that the session needs to
// be updated. It also means that if a subscription on same subject with same
// QoS already exist, we should not be recreating the subscription/JS durable,
// since it was already done when processing the CONNECT protocol.
//
// Runs from the client's readLoop.
// Lock not held on entry, but session is in the locked map.
func (as *mqttAccountSessionManager) processSubs(sess *mqttSession, c *client,
	filters []*mqttFilter, fromSubProto, trace bool) ([]*subscription, error) {

	// Helper to determine if we need to create a separate top-level
	// subscription for a wildcard.
	fwc := func(subject string) (bool, string, string) {
		if !mqttNeedSubForLevelUp(subject) {
			return false, _EMPTY_, _EMPTY_
		}
		// Say subject is "foo.>", remove the ".>" so that it becomes "foo"
		fwcsubject := subject[:len(subject)-2]
		// Change the sid to "foo fwc"
		fwcsid := fwcsubject + mqttMultiLevelSidSuffix

		return true, fwcsubject, fwcsid
	}

	rmSubjects := map[string]uint64{}
	// Preload retained messages for all requested subscriptions.  Also, since
	// it's the first iteration over the filter list, do some cleanup.
	for _, f := range filters {
		// A filter flagged with a failure reason at parse time (e.g. a shared
		// subscription) is not processed; the code becomes the SUBACK byte.
		if f.reason >= mqttSubAckFailure {
			f.qos = f.reason
			continue
		}
		if f.qos > 2 {
			f.qos = 2
		}
		if c.mqtt.downgradeQoS2Sub && f.qos == 2 {
			c.Warnf("Downgrading subscription QoS2 to QoS1 for %q, as configured", f.filter)
			f.qos = 1
		}

		// Do not allow subscribing to our internal subjects.
		//
		// TODO: (levb: not sure why since one can subscribe to `#` and it'll
		// include everything; I guess this would discourage? Otherwise another
		// candidate for DO NOT DELIVER prefix list).
		if strings.HasPrefix(f.filter, mqttSubPrefix) ||
			strings.HasPrefix(f.filter, mqttPubRelDeliverySubjectPrefix) {
			f.qos = mqttSubAckFailure
			continue
		}

		if f.qos == 2 {
			if err := sess.ensurePubRelConsumerSubscription(c); err != nil {
				c.Errorf("failed to initialize PUBREL processing: %v", err)
				f.qos = mqttSubAckFailure
				continue
			}
		}

		// Find retained messages.
		if fromSubProto {
			as.addRetainedSubjectsForSubject(rmSubjects, f.filter)
			if need, subject, _ := fwc(f.filter); need {
				as.addRetainedSubjectsForSubject(rmSubjects, subject)
			}
		}
	}

	var rms map[string]*mqttRetainedMsg
	if len(rmSubjects) > 0 {
		// Make the best effort to load retained messages.
		rms = as.loadRetainedMessages(rmSubjects, c)
	}

	// Small helper to add the consumer config to the session.
	addJSConsToSess := func(sid string, cc *ConsumerConfig) {
		if cc == nil {
			return
		}
		if sess.cons == nil {
			sess.cons = make(map[string]*ConsumerConfig)
		}
		sess.cons[sid] = cc
	}

	var err error
	subs := make([]*subscription, 0, len(filters))
	for _, f := range filters {
		// Skip what's already been identified as a failure (0x80 or any v5
		// error reason code).
		if f.qos >= mqttSubAckFailure {
			continue
		}
		subject := f.filter
		bsubject := []byte(subject)
		sid := subject
		bsid := bsubject
		isReserved := isMQTTReservedSubscription(subject)

		var jscons *ConsumerConfig
		var jssub *subscription

		// Note that if a subscription already exists on this subject, the
		// existing sub is returned. Need to update the qos.
		var sub *subscription
		var err error

		const processShadowSubs = true

		as.mu.Lock()
		sess.mu.Lock()
		sub, err = sess.processSub(c,
			bsubject, bsid, isReserved, f.qos, // main subject
			_EMPTY_, mqttDeliverMsgCbQoS0, // no jsDur for QOS0
			processShadowSubs,
			rms, trace, as)
		sess.mu.Unlock()
		as.mu.Unlock()

		if err != nil {
			f.qos = mqttSubAckFailure
			sess.cleanupFailedSub(c, sub, jscons, jssub)
			continue
		}

		// This will create (if not already exist) a JS consumer for
		// subscriptions of QoS >= 1. But if a JS consumer already exists and
		// the subscription for same subject is now a QoS==0, then the JS
		// consumer will be deleted.
		jscons, jssub, err = sess.processJSConsumer(c, subject, sid, f.qos, fromSubProto)
		if err != nil {
			f.qos = mqttSubAckFailure
			sess.cleanupFailedSub(c, sub, jscons, jssub)
			continue
		}

		// Process the wildcard subject if needed.
		if need, fwcsubject, fwcsid := fwc(subject); need {
			var fwjscons *ConsumerConfig
			var fwjssub *subscription
			var fwcsub *subscription

			// See note above about existing subscription.
			as.mu.Lock()
			sess.mu.Lock()
			fwcsub, err = sess.processSub(c,
				[]byte(fwcsubject), []byte(fwcsid), isReserved, f.qos, // FWC (top-level wildcard) subject
				_EMPTY_, mqttDeliverMsgCbQoS0, // no jsDur for QOS0
				processShadowSubs,
				rms, trace, as)
			sess.mu.Unlock()
			as.mu.Unlock()
			if err != nil {
				// c.processSub already called c.Errorf(), so no need here.
				f.qos = mqttSubAckFailure
				sess.cleanupFailedSub(c, sub, jscons, jssub)
				continue
			}

			fwjscons, fwjssub, err = sess.processJSConsumer(c, fwcsubject, fwcsid, f.qos, fromSubProto)
			if err != nil {
				// c.processSub already called c.Errorf(), so no need here.
				f.qos = mqttSubAckFailure
				sess.cleanupFailedSub(c, sub, jscons, jssub)
				sess.cleanupFailedSub(c, fwcsub, fwjscons, fwjssub)
				continue
			}

			subs = append(subs, fwcsub)
			addJSConsToSess(fwcsid, fwjscons)
		}

		subs = append(subs, sub)
		addJSConsToSess(sid, jscons)
	}

	if fromSubProto {
		err = sess.update(filters, true)
	}

	return subs, err
}

// Retained publish messages matching this subscription are serialized in the
// subscription's `prm` mqtt writer. This buffer will be queued for outbound
// after the subscription is processed and SUBACK is sent or possibly when
// server processes an incoming published message matching the newly
// registered subscription.
//
// Runs from the client's readLoop.
// Account session manager lock held on entry.
// Session lock held on entry.
func (as *mqttAccountSessionManager) serializeRetainedMsgsForSub(rms map[string]*mqttRetainedMsg, sess *mqttSession, c *client, sub *subscription, trace bool) {
	if as.retmsgs.Size() == 0 || len(rms) == 0 {
		return
	}
	toTrace := []mqttPublish{}
	as.retmsgs.Match(sub.subject, func(subj []byte, _ *mqttRetainedMsgRef) {
		rm := rms[string(subj)]
		if rm == nil {
			// This should not happen since we pre-load messages into rms before
			// calling serialize.
			return
		}
		// MQTT 5.0 Message Expiry Interval: an expired retained message must not be
		// delivered. The stored copy is reaped by its per-message TTL; this guards
		// the window where the in-memory ref/cache still points at it. Spec5
		// [3.3.2.3.3].
		if !rm.expires.IsZero() && !time.Now().Before(rm.expires) {
			return
		}
		// A broad wildcard subscription can overlap a subscribe deny clause.
		c.mu.Lock()
		denied := c.mperms != nil && c.checkDenySub(string(subj))
		c.mu.Unlock()
		if denied {
			return
		}
		var pi uint16
		qos := min(mqttGetQoS(rm.Flags), sub.mqtt.qos)
		if c.mqtt.rejectQoS2Pub && qos == 2 {
			c.Warnf("Rejecting retained message with QoS2 for subscription %q, as configured", sub.subject)
			return
		}
		if qos > 0 {
			pi = sess.trackPublishRetained()

			// If we failed to get a PI for this message, send it as a QoS0, the
			// best we can do?
			if pi == 0 {
				qos = 0
			}
		}

		// MQTT 5.0 Message Expiry Interval: a v5 subscriber must receive the
		// interval reduced by the time the retained message has been waiting in the
		// server. Spec5 [3.3.2.3.3]. 3.1.1 subscribers get no properties section.
		props := rm.Props
		if c.mqtt.proto == mqttProtoLevel5 && !rm.expires.IsZero() {
			rem := uint32(time.Until(rm.expires).Seconds())
			if rem < 1 {
				rem = 1
			}
			props = mqttSetMessageExpiry(rm.Props, rem)
		}

		// Need to use the subject for the retained message, not the `sub` subject.
		// We can find the published retained message in rm.sub.subject.
		// Set the RETAIN flag: [MQTT-3.3.1-8].
		flags, headerBytes := mqttMakePublishHeader(pi, qos, false, true, c.mqtt.proto == mqttProtoLevel5, []byte(rm.Topic), props, len(rm.Msg))

		// MQTT 5.0 Maximum Packet Size: skip a retained message that would exceed
		// the client's limit rather than send an oversized packet (which a strict
		// client rejects as a protocol error). Discarding is spec-correct: the
		// message is treated as delivered. Release the packet identifier if one
		// was allocated (the session lock is held on entry). Spec5 [3.1.2.11.4].
		if mp := c.mqtt.maxPacketSize; mp != 0 && len(headerBytes)+len(rm.Msg) > int(mp) {
			if pi != 0 {
				sess.untrackPublish(pi)
			}
			return
		}
		c.mu.Lock()
		sub.mqtt.prm = append(sub.mqtt.prm, headerBytes, rm.Msg)
		c.mu.Unlock()
		if trace {
			toTrace = append(toTrace, mqttPublish{
				topic: []byte(rm.Topic),
				flags: flags,
				pi:    pi,
				sz:    len(rm.Msg),
			})
		}
	})
	for _, pp := range toTrace {
		c.traceOutOp("PUBLISH", []byte(mqttPubTrace(&pp)))
	}
}

// Appends the stored message subjects for all retained message records that
// match the given subscription's `subject` (which could have wildcards).
//
// Account session manager NOT lock held on entry.
func (as *mqttAccountSessionManager) addRetainedSubjectsForSubject(list map[string]uint64, topSubject string) {
	as.mu.RLock()
	defer as.mu.RUnlock()

	if as.retmsgs.Size() == 0 {
		return
	}

	as.retmsgs.Match(stringToBytes(topSubject), func(subj []byte, ret *mqttRetainedMsgRef) {
		subject := string(subj)
		if _, ok := list[subject]; ok {
			return
		}
		if seq := ret.sseq; seq > 0 {
			list[subject] = seq
		}
	})
}

type warner interface {
	Warnf(format string, v ...any)
}

// Loads a list of retained messages given a list of stored message subjects.
func (as *mqttAccountSessionManager) loadRetainedMessages(subjects map[string]uint64, w warner) map[string]*mqttRetainedMsg {
	rms := make(map[string]*mqttRetainedMsg, len(subjects))
	ss := []string{}
	for s := range subjects {
		if rm := as.getCachedRetainedMsg(s); rm != nil {
			rms[s] = rm
		} else {
			ss = append(ss, mqttRetainedMsgsStreamSubject+s)
		}
	}

	if len(ss) == 0 {
		return rms
	}

	// Although we have the stream sequence for a given subject, we still use
	// the load with "last for subject" because it will cover the cases where a
	// new retained message has arrived since we collected the subject/seq pair.
	// If we were doing a load "by seq" and the message is not found, we would
	// incorrectly remove the retained message from our map.
	results, err := as.jsa.loadLastMsgForMulti(mqttRetainedMsgsStreamName, ss)
	// If an error occurred, warn, but then proceed with what we got.
	if err != nil {
		w.Warnf("error loading retained messages: %v", err)
	}
	for i, result := range results {
		if result == nil {
			continue // skip requests that timed out
		}
		if err := result.ToError(); err != nil {
			// Skip the "$MQTT.rmsgs." prefix...
			subj := ss[i][len(mqttRetainedMsgsStreamSubject):]
			if IsNatsErr(err, JSNoMessageFoundErr) {
				// If there is no message for that subject, delete from our map.
				// The good thing here is that we handle the race where a retained
				// message may just arrive and be replacing it in the map. The
				// removeRetainedMsg() function below will not remove if the sequence
				// does not match.
				seq := subjects[subj]
				as.removeRetainedMsg(subj, seq)
				// Expected when a per-message TTL reaped an expired retained
				// message; the stale index entry is cleaned up, no warning.
				continue
			}
			w.Warnf("failed to load retained message for subject %q: %v", subj, err)
			continue
		}
		rm, err := mqttDecodeRetainedMessage(result.Message.Subject, result.Message.Header, result.Message.Data)
		if err != nil {
			// Unlikely that we can recover from that, so remove the message.
			// (see comment above if failing to load the message).
			subj := ss[i][len(mqttRetainedMsgsStreamSubject):]
			seq := subjects[subj]
			as.removeRetainedMsg(subj, seq)
			w.Warnf("failed to decode retained message for subject %q: %v", subj, err)
			continue
		}

		// Add the loaded retained message to the cache, and to the results map.
		// We don't need setCachedRetainedMsg() to clone the `rm.Msg` bytes slice
		// since we own it.
		as.setCachedRetainedMsg(rm.Subject, rm, false, false)
		rms[rm.Subject] = rm
	}
	return rms
}

// Composes a NATS message for a storeable mqttRetainedMsg.
// If the body is empty, the flags are encoded in a way that will cause older
// servers to fail to decode the message in processRetainedMsg callback and
// will simply ignore it, which is what we want.
func mqttEncodeRetainedMessage(rm *mqttRetainedMsg) (natsMsg []byte, headerLen int) {
	return mqttEncodeRetainedMessageTTL(rm, true)
}

// withTTL=false skips the JetStream per-message TTL header (degraded mode: the
// stream does not allow it); the expiry deadline header is still written so
// delivery-side expiry keeps working.
func mqttEncodeRetainedMessageTTL(rm *mqttRetainedMsg, withTTL bool) (natsMsg []byte, headerLen int) {
	delRM := len(rm.Msg) == 0

	// MQTT 5.0 Message Expiry Interval: for a live retained message with an
	// expiry, carry the absolute deadline (so the remaining interval can be
	// recomputed on replay) plus a JetStream per-message TTL for the remaining
	// lifetime (so the stored copy is dropped once it expires). Delete markers
	// (empty payload) never carry expiry. Spec5 [3.3.2.3.3].
	var expStr, ttlStr string
	if !delRM && !rm.expires.IsZero() {
		expStr = strconv.FormatInt(rm.expires.UnixNano(), 10)
		// Round the remaining lifetime up so JetStream never deletes the retained
		// copy before its deadline (truncating a 1.99s remainder to 1s would drop
		// it almost a second early). At least 1s, JetStream's minimum.
		secs := int64((time.Until(rm.expires) + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		ttlStr = strconv.FormatInt(secs, 10)
		if !withTTL {
			ttlStr = _EMPTY_
		}
	}

	// No need to encode the subject, we can restore it from topic.
	l := len(hdrLine)
	l += len(mqttNatsRetainedMessageTopic) + 1 + len(rm.Topic) + 2 // 1 byte for ':', 2 bytes for CRLF
	if rm.Origin != _EMPTY_ {
		l += len(mqttNatsRetainedMessageOrigin) + 1 + len(rm.Origin) + 2 // 1 byte for ':', 2 bytes for CRLF
	}
	if rm.Source != _EMPTY_ {
		l += len(mqttNatsRetainedMessageSource) + 1 + len(rm.Source) + 2 // 1 byte for ':', 2 bytes for CRLF
	}
	if len(rm.Props) > 0 {
		l += len(mqttNatsRetainedMessageProps) + 1 + base64.StdEncoding.EncodedLen(len(rm.Props)) + 2 // 1 byte for ':', 2 bytes for CRLF
	}
	if expStr != _EMPTY_ {
		l += len(mqttNatsRetainedMessageExpiry) + 1 + len(expStr) + 2 // 1 byte for ':', 2 bytes for CRLF
	}
	if ttlStr != _EMPTY_ {
		l += len(JSMessageTTL) + 1 + len(ttlStr) + 1 + 2 // 1 byte for ':', 1 for 's', 2 bytes for CRLF
	}
	l += len(mqttNatsRetainedMessageFlags) + 1 + 2 + 2 // 1 byte for ':', 2 bytes for the flags, 2 bytes for CRLF
	l += 2                                             // 2 bytes for the extra CRLF after the header
	if delRM {
		l++ // Will add the delete marker before the flag
	} else {
		l += len(rm.Msg)
	}

	buf := bytes.NewBuffer(make([]byte, 0, l))

	buf.WriteString(hdrLine)

	buf.WriteString(mqttNatsRetainedMessageTopic)
	buf.WriteByte(':')
	buf.WriteString(rm.Topic)
	buf.WriteString(_CRLF_)

	buf.WriteString(mqttNatsRetainedMessageFlags)
	buf.WriteByte(':')
	if delRM {
		buf.WriteByte(mqttRetainedFlagDelMarker)
	}
	buf.WriteString(strconv.FormatUint(uint64(rm.Flags), 16))
	buf.WriteString(_CRLF_)

	if rm.Origin != _EMPTY_ {
		buf.WriteString(mqttNatsRetainedMessageOrigin)
		buf.WriteByte(':')
		buf.WriteString(rm.Origin)
		buf.WriteString(_CRLF_)
	}
	if rm.Source != _EMPTY_ {
		buf.WriteString(mqttNatsRetainedMessageSource)
		buf.WriteByte(':')
		buf.WriteString(rm.Source)
		buf.WriteString(_CRLF_)
	}
	if len(rm.Props) > 0 {
		buf.WriteString(mqttNatsRetainedMessageProps)
		buf.WriteByte(':')
		buf.WriteString(base64.StdEncoding.EncodeToString(rm.Props))
		buf.WriteString(_CRLF_)
	}

	if expStr != _EMPTY_ {
		buf.WriteString(mqttNatsRetainedMessageExpiry)
		buf.WriteByte(':')
		buf.WriteString(expStr)
		buf.WriteString(_CRLF_)
	}
	if ttlStr != _EMPTY_ {
		buf.WriteString(JSMessageTTL)
		buf.WriteByte(':')
		buf.WriteString(ttlStr)
		buf.WriteByte('s')
		buf.WriteString(_CRLF_)
	}

	// End of header, finalize
	buf.WriteString(_CRLF_)
	headerLen = buf.Len()
	buf.Write(rm.Msg)
	return buf.Bytes(), headerLen
}

func mqttSliceHeaders(headers map[string][]byte, hdr []byte) {
	// Skip the hdrLine
	if !bytes.HasPrefix(hdr, stringToBytes(hdrLine)) {
		return
	}
	crLFAsBytes := stringToBytes(CR_LF)
	for i := len(hdrLine); i < len(hdr); {
		// Search for key/val delimiter.
		del := bytes.IndexByte(hdr[i:], ':')
		// Not found or key is length 0, we stop.
		if del < 0 || del == i {
			break
		}
		keyStart := i
		// Walk back to remove spaces between the key and ':' if applicable.
		index := keyStart + del - 1
		for index > keyStart && hdr[index] == ' ' {
			index--
		}
		key := hdr[keyStart : index+1]
		// If what we had is only spaces, we stop.
		if len(key) == 0 {
			break
		}
		i += del + 1
		valStart := i
		// Search for `\r\n`.
		nl := bytes.Index(hdr[valStart:], crLFAsBytes)
		// If we don't find, we stop.
		if nl < 0 {
			break
		}
		// Look if the caller is interested in this key.
		if _, ok := headers[bytesToString(key)]; ok {
			index := valStart
			// Remove possible spaces between the ':' and the value.
			for index < valStart+nl && hdr[index] == ' ' {
				index++
			}
			// Create a slice and limit capacity to the value range.
			val := hdr[index : valStart+nl : valStart+nl]
			// Record in the caller's map the value for this key.
			headers[bytesToString(key)] = val
		}
		// Reposition to past the `\r\n`.
		i += nl + 2
	}
}

// Decodes a retained message based on the content of the header `h`.
// The returned `*mqttRetainedMsg` object will hold a reference to `m`.
// If the buffer `m` is not owned by the caller, it is the caller
// responsibility to make a copy of the byte slice.
func mqttDecodeRetainedMessage(subject string, h, m []byte) (*mqttRetainedMsg, error) {
	headers := map[string][]byte{
		mqttNatsRetainedMessageOrigin: nil,
		mqttNatsRetainedMessageFlags:  nil,
		mqttNatsRetainedMessageSource: nil,
		mqttNatsRetainedMessageProps:  nil,
		mqttNatsRetainedMessageExpiry: nil,
	}
	var rm *mqttRetainedMsg
	// Retrieve the values for the above headers.
	mqttSliceHeaders(headers, h)
	// Get the flag header.
	fHeader := headers[mqttNatsRetainedMessageFlags]
	// If we don't, it could be that this is an old retained message that
	// was JSON encoded.
	if len(fHeader) > 0 {
		if len(fHeader) > 1 && fHeader[0] == mqttRetainedFlagDelMarker {
			fHeader = fHeader[1:]
		}
		flagsUint, err := strconv.ParseUint(bytesToString(fHeader), 16, 8)
		if err != nil {
			// Since the error is currently not reported in the server, we
			// will simply replace with this one.
			return nil, errMQTTInvalidRetainFlags
		}
		rm = &mqttRetainedMsg{
			Flags:  byte(flagsUint),
			Origin: string(headers[mqttNatsRetainedMessageOrigin]),
			Source: string(headers[mqttNatsRetainedMessageSource]),
			Msg:    m,
		}
		// MQTT 5.0 properties block (base64). Absent for older stored messages.
		// Validate before keeping it: the retained stream could contain a
		// crafted Nmqtt-RProps from a non-MQTT publisher, and rm.Props is later
		// written verbatim into outbound PUBLISH packets.
		if enc := headers[mqttNatsRetainedMessageProps]; len(enc) > 0 {
			if raw, err := base64.StdEncoding.DecodeString(bytesToString(enc)); err == nil {
				rm.Props = mqttValidateForwardProps(raw)
			}
		}
		// MQTT 5.0 Message Expiry Interval: absolute deadline (Unix nanoseconds).
		if exp := headers[mqttNatsRetainedMessageExpiry]; len(exp) > 0 {
			if ns, err := strconv.ParseInt(bytesToString(exp), 10, 64); err == nil && ns > 0 {
				rm.expires = time.Unix(0, ns)
			}
		}
	} else {
		if err := json.Unmarshal(m, &rm); err != nil {
			return nil, err
		}
		// Same validation as the header path above: a JSON record from a
		// non-MQTT publisher could carry crafted Props.
		rm.Props = mqttValidateForwardProps(rm.Props)
	}
	// Now check that the values are correct.
	//
	// For "Flags", anything at or above binary (1111) is too big.
	if rm.Flags >= mqttPacketFlagMask {
		return nil, errMQTTInvalidRetainFlags
	}
	if qos := mqttGetQoS(rm.Flags); qos > 2 {
		return nil, errMQTTInvalidRetainFlags
	}
	// We store `Topic` in the retained message because we used to store
	// all retained messages under the same subject `$MQTT_rmsgs` in
	// the retained messages stream. That is no longer the case, and to
	// cover setups where the retained message stream is sourced from another
	// account and has some subject transforms, simply reconstruct the
	// topic/subject based on the `subject` passed to this function.
	rm.Subject = strings.TrimPrefix(subject, mqttRetainedMsgsStreamSubject)
	rm.Topic = bytesToString(natsSubjectStrToMQTTTopic(rm.Subject))
	return rm, nil
}

// Creates the session stream (limit msgs of 1) for this client ID if it does
// not already exist. If it exists, recover the single record to rebuild the
// state of the session. If there is a session record but this session is not
// registered in the runtime of this server, then a request is made to the
// owner to close the client associated with this session since specification
// [MQTT-3.1.4-2] specifies that if the ClientId represents a Client already
// connected to the Server then the Server MUST disconnect the existing client.
//
// Runs from the client's readLoop.
// Lock not held on entry, but session is in the locked map.
func (as *mqttAccountSessionManager) createOrRestoreSession(clientID string, opts *Options) (*mqttSession, bool, error) {
	jsa := &as.jsa

	hash := getHash(clientID)
	smsg, err := jsa.loadSessionMsg(as.domainTk, hash)
	if err != nil {
		if isErrorOtherThan(err, JSNoMessageFoundErr) {
			return nil, false, fmt.Errorf("loading session record: %w", err)
		}
		// Message not found, so reate the session...
		// Create a session and indicate that this session did not exist.
		sess := mqttSessionCreate(jsa, clientID, hash, 0, opts)
		sess.domainTk = as.domainTk
		return sess, false, nil
	}
	// We need to recover the existing record now.
	ps := &mqttPersistedSession{}
	if err := json.Unmarshal(smsg.Data, ps); err != nil {
		return nil, false, fmt.Errorf("unmarshal of session record at sequence %v: %w", smsg.Sequence, err)
	}
	if ps.ID != clientID {
		return nil, false, errMQTTSessionCollision
	}

	// Restore this session (even if we don't own it), the caller will do the right thing.
	sess := mqttSessionCreate(jsa, clientID, hash, smsg.Sequence, opts)
	sess.domainTk = as.domainTk
	sess.clean = ps.Clean
	sess.subs = ps.Subs
	sess.cons = ps.Cons
	sess.pubRelConsumer = ps.PubRel
	as.addSession(sess, true)
	return sess, true, nil
}

// Sends a request to delete a message, but does not wait for the response.
//
// No lock held on entry.
func (as *mqttAccountSessionManager) deleteRetainedMsg(seq uint64) {
	as.jsa.deleteMsg(mqttRetainedMsgsStreamName, seq, false)
}

// Sends a message indicating that a retained message on a given subject and stream sequence
// is being removed.
// NOTE: This is maintained for backward compatibility reasons. Should be removed in 2.14/2.15?
func (as *mqttAccountSessionManager) notifyRetainedMsgDeleted(subject string, seq uint64) {
	req := mqttRetMsgDel{
		Subject: subject,
		Seq:     seq,
	}
	b, _ := json.Marshal(&req)
	jsa := &as.jsa
	jsa.sendq.push(&mqttJSPubMsg{
		subj: jsa.rplyr + mqttJSARetainedMsgDel,
		msg:  b,
	})
}

func (as *mqttAccountSessionManager) transferUniqueSessStreamsToMuxed(log *Server) {
	// Set retry to true, will be set to false on success.
	retry := true
	defer func() {
		if retry {
			next := mqttDefaultTransferRetry
			log.Warnf("Failed to transfer all MQTT session streams, will try again in %v", next)
			time.AfterFunc(next, func() { as.transferUniqueSessStreamsToMuxed(log) })
		}
	}()

	jsa := &as.jsa
	sni, err := jsa.newRequestEx(mqttJSAStreamNames, JSApiStreams, _EMPTY_, 0, nil)
	if err != nil {
		log.Errorf("Unable to transfer MQTT session streams: %v", err)
		return
	}
	snames := sni.(*JSApiStreamNamesResponse)
	if snames.Error != nil {
		log.Errorf("Unable to transfer MQTT session streams: %v", snames.ToError())
		return
	}
	var oldMQTTSessStreams []string
	for _, sn := range snames.Streams {
		if strings.HasPrefix(sn, mqttSessionsStreamNamePrefix) {
			oldMQTTSessStreams = append(oldMQTTSessStreams, sn)
		}
	}
	ns := len(oldMQTTSessStreams)
	if ns == 0 {
		// Nothing to do
		retry = false
		return
	}
	log.Noticef("Transferring %v MQTT session streams...", ns)
	for _, sn := range oldMQTTSessStreams {
		log.Noticef("  Transferring stream %q to %q", sn, mqttSessStreamName)
		smsg, err := jsa.loadLastMsgFor(sn, sn)
		if err != nil {
			log.Errorf("   Unable to load session record: %v", err)
			return
		}
		ps := &mqttPersistedSession{}
		if err := json.Unmarshal(smsg.Data, ps); err != nil {
			log.Warnf("    Unable to unmarshal the content of this stream, may not be a legitimate MQTT session stream, skipping")
			continue
		}
		// Store record to MQTT session stream
		if _, err := jsa.storeSessionMsg(as.domainTk, getHash(ps.ID), 0, smsg.Data); err != nil {
			log.Errorf("    Unable to transfer the session record: %v", err)
			return
		}
		jsa.deleteStream(sn)
	}
	log.Noticef("Transfer of %v MQTT session streams done!", ns)
	retry = false
}

func (as *mqttAccountSessionManager) transferRetainedToPerKeySubjectStream(log *Server) error {
	jsa := &as.jsa
	var processed int
	var transferred int

	start := time.Now()
	deadline := start.Add(mqttRetainedTransferTimeout)
	for {
		// Try and look up messages on the original undivided "$MQTT.rmsgs" subject.
		// If nothing is returned here, we assume to have migrated all old messages.
		smsg, err := jsa.loadNextMsgFor(mqttRetainedMsgsStreamName, "$MQTT.rmsgs")
		if IsNatsErr(err, JSNoMessageFoundErr) {
			// We've ran out of messages to transfer, done.
			break
		}
		if err != nil {
			log.Warnf("    Unable to transfer a retained message: failed to load from '$MQTT.rmsgs': %s", err)
			return err
		}

		// Unmarshal the message so that we can obtain the subject name. Do not
		// use mqttDecodeRetainedMessage() here because these messages are from
		// older versions, and contain the full JSON encoding in payload.
		var rmsg mqttRetainedMsg
		if err = json.Unmarshal(smsg.Data, &rmsg); err == nil {
			// Store the message again, this time with the new per-key subject.
			subject := mqttRetainedMsgsStreamSubject + rmsg.Subject
			if _, err = jsa.storeMsg(subject, 0, smsg.Data); err != nil {
				log.Errorf("    Unable to transfer the retained message with sequence %d: %v", smsg.Sequence, err)
			}
			transferred++
		} else {
			log.Warnf("    Unable to unmarshal retained message with sequence %d, skipping", smsg.Sequence)
		}

		// Delete the original message.
		if err := jsa.deleteMsg(mqttRetainedMsgsStreamName, smsg.Sequence, true); err != nil {
			log.Errorf("    Unable to clean up the retained message with sequence %d: %v", smsg.Sequence, err)
			return err
		}
		processed++

		now := time.Now()
		if now.After(deadline) {
			err := fmt.Errorf("timed out while transferring retained messages from '$MQTT.rmsgs' after %v, %d processed, %d successfully transferred", now.Sub(start), processed, transferred)
			log.Noticef(err.Error())
			return err
		}
	}
	if processed > 0 {
		log.Noticef("Processed %d messages from '$MQTT.rmsgs', successfully transferred %d in %v", processed, transferred, time.Since(start))
	} else {
		log.Debugf("No messages found to transfer from '$MQTT.rmsgs'")
	}
	return nil
}

func (as *mqttAccountSessionManager) getCachedRetainedMsg(subject string) *mqttRetainedMsg {
	v, ok := as.rmsCache.Load(subject)
	if !ok {
		return nil
	}
	rm := v.(*mqttRetainedMsg)
	if rm.expiresFromCache.Before(time.Now()) {
		as.rmsCache.Delete(subject)
		return nil
	}
	// MQTT 5.0 Message Expiry Interval: drop an expired retained message rather
	// than serve a stale copy from the cache. Spec5 [3.3.2.3.3].
	if !rm.expires.IsZero() && !time.Now().Before(rm.expires) {
		as.rmsCache.Delete(subject)
		return nil
	}
	return rm
}

// If cache is enabled, the expiration for the `rm` is bumped by
// `mqttRetainedCacheTTL` seconds.
// If `onlyReplace` is true, then the `rm` object is stored in the cache using
// the `subject` key only if there was already an object stored under that key.
// If `copyMsgBytes` is true, then the `rm.Msg` bytes are copied (because it
// references some buffer that is not owned by the caller).
//
// Note: currently `onlyReplace` and `cloneMsgBytes` always have the same
// value (all `true` or all `false`) however we use different booleans to
// better express the intent.
func (as *mqttAccountSessionManager) setCachedRetainedMsg(subject string, rm *mqttRetainedMsg, onlyReplace, copyMsgBytes bool) {
	if rm == nil {
		return
	}
	rm.expiresFromCache = time.Now().Add(mqttRetainedCacheTTL)
	if onlyReplace {
		if _, ok := as.rmsCache.Load(subject); !ok {
			return
		}
	}
	if copyMsgBytes {
		rm.Msg = copyBytes(rm.Msg)
	}
	as.rmsCache.Store(subject, rm)
}

//////////////////////////////////////////////////////////////////////////////
//
// MQTT session related functions
//
//////////////////////////////////////////////////////////////////////////////

// Returns a new mqttSession object with max ack pending set based on
// option or use mqttDefaultMaxAckPending if no option set.
func mqttSessionCreate(jsa *mqttJSA, id, idHash string, seq uint64, opts *Options) *mqttSession {
	maxp := opts.MQTT.MaxAckPending
	if maxp == 0 {
		maxp = mqttDefaultMaxAckPending
	}

	return &mqttSession{
		jsa:                    jsa,
		id:                     id,
		idHash:                 idHash,
		seq:                    seq,
		maxp:                   maxp,
		pubRelSubject:          mqttPubRelSubjectPrefix + idHash,
		pubRelDeliverySubject:  mqttPubRelDeliverySubjectPrefix + idHash,
		pubRelDeliverySubjectB: []byte(mqttPubRelDeliverySubjectPrefix + idHash),
	}
}

// Persists a session. Note that if the session's current client does not match
// the given client, nothing is done.
//
// Lock not held on entry.
func (sess *mqttSession) save() error {
	sess.mu.Lock()
	ps := mqttPersistedSession{
		Origin: sess.jsa.id,
		ID:     sess.id,
		Clean:  sess.clean,
		Subs:   sess.subs,
		Cons:   sess.cons,
		PubRel: sess.pubRelConsumer,
	}
	b, _ := json.Marshal(&ps)

	domainTk, cidHash := sess.domainTk, sess.idHash
	seq := sess.seq
	sess.mu.Unlock()

	var hdr int
	if seq != 0 {
		bb := bytes.Buffer{}
		bb.WriteString(hdrLine)
		bb.WriteString(JSExpectedLastSubjSeq)
		bb.WriteString(":")
		bb.WriteString(strconv.FormatInt(int64(seq), 10))
		bb.WriteString(CR_LF)
		bb.WriteString(CR_LF)
		hdr = bb.Len()
		bb.Write(b)
		b = bb.Bytes()
	}

	resp, err := sess.jsa.storeSessionMsg(domainTk, cidHash, hdr, b)
	if err != nil {
		return fmt.Errorf("unable to persist session %q (seq=%v): %v", ps.ID, seq, err)
	}
	sess.mu.Lock()
	sess.seq = resp.Sequence
	sess.mu.Unlock()
	return nil
}

// Clear the session.
//
// Runs from the client's readLoop.
// Lock not held on entry, but session is in the locked map.
func (sess *mqttSession) clear(noWait bool) error {
	var durs []string
	var pubRelDur string

	sess.mu.Lock()
	id := sess.id
	seq := sess.seq
	if l := len(sess.cons); l > 0 {
		durs = make([]string, 0, l)
	}
	for sid, cc := range sess.cons {
		delete(sess.cons, sid)
		durs = append(durs, cc.Durable)
	}
	if sess.pubRelConsumer != nil {
		pubRelDur = sess.pubRelConsumer.Durable
	}

	sess.subs = nil
	sess.pendingPublish = nil
	sess.pendingPubRel = nil
	sess.cpending = nil
	sess.pubRelConsumer = nil
	sess.seq = 0
	sess.tmaxack = 0
	sess.mu.Unlock()

	for _, dur := range durs {
		if _, err := sess.jsa.deleteConsumer(mqttStreamName, dur, noWait); isErrorOtherThan(err, JSConsumerNotFoundErr) {
			return fmt.Errorf("unable to delete consumer %q for session %q: %v", dur, sess.id, err)
		}
	}
	if pubRelDur != _EMPTY_ {
		_, err := sess.jsa.deleteConsumer(mqttOutStreamName, pubRelDur, noWait)
		if isErrorOtherThan(err, JSConsumerNotFoundErr) {
			return fmt.Errorf("unable to delete consumer %q for session %q: %v", pubRelDur, sess.id, err)
		}
	}

	if seq > 0 {
		err := sess.jsa.deleteMsg(mqttSessStreamName, seq, !noWait)
		// Ignore the various errors indicating that the message (or sequence)
		// is already deleted, can happen in a cluster.
		if isErrorOtherThan(err, JSSequenceNotFoundErrF) {
			if isErrorOtherThan(err, JSStreamMsgDeleteFailedF) || !strings.Contains(err.Error(), ErrStoreMsgNotFound.Error()) {
				return fmt.Errorf("unable to delete session %q record at sequence %v: %v", id, seq, err)
			}
		}
	}
	return nil
}

// This will update the session record for this client in the account's MQTT
// sessions stream if the session had any change in the subscriptions.
//
// Runs from the client's readLoop.
// Lock not held on entry, but session is in the locked map.
func (sess *mqttSession) update(filters []*mqttFilter, add bool) error {
	// Evaluate if we need to persist anything.
	var needUpdate bool
	for _, f := range filters {
		if add {
			if f.qos >= mqttSubAckFailure {
				continue
			}
			if qos, ok := sess.subs[f.filter]; !ok || qos != f.qos {
				if sess.subs == nil {
					sess.subs = make(map[string]byte)
				}
				sess.subs[f.filter] = f.qos
				needUpdate = true
			}
		} else {
			if _, ok := sess.subs[f.filter]; ok {
				delete(sess.subs, f.filter)
				needUpdate = true
			}
		}
	}
	var err error
	if needUpdate {
		err = sess.save()
	}
	return err
}

func (sess *mqttSession) bumpPI() uint16 {
	var avail bool
	next := sess.last_pi
	for i := 0; i < 0xFFFF; i++ {
		next++
		if next == 0 {
			next = 1
		}

		_, usedInPublish := sess.pendingPublish[next]
		_, usedInPubRel := sess.pendingPubRel[next]
		if !usedInPublish && !usedInPubRel {
			sess.last_pi = next
			avail = true
			break
		}
	}
	if !avail {
		return 0
	}
	return sess.last_pi
}

// effectiveMaxAck returns the maximum number of unacknowledged QoS1/2 PUBLISH
// this session may have in flight: the configured MaxAckPending, further capped
// by the client's MQTT 5.0 Receive Maximum when one was advertised (rmax != 0).
//
// Lock held on entry.
func (sess *mqttSession) effectiveMaxAck() int {
	m := sess.maxp
	if sess.rmax != 0 && sess.rmax < m {
		m = sess.rmax
	}
	return int(m)
}

// qos12InflightForCap counts in-flight QoS 1/2 PUBLISHes against effectiveMaxAck.
// With a Receive Maximum, QoS 2 messages awaiting PUBCOMP (pendingPubRel) still
// count: Spec5 [4.9] frees the quota only on PUBACK/PUBCOMP or a failed PUBREC.
// Without one, the cap is JetStream MaxAckPending, which those were acked out of.
//
// Lock held on entry
func (sess *mqttSession) qos12InflightForCap() int {
	n := len(sess.pendingPublish)
	if sess.rmax != 0 {
		n += len(sess.pendingPubRel)
	}
	return n
}

// dropUnredeliverableRetained releases pending retained (QoS1/2) deliveries,
// identified by an empty jsAckSubject: they have no JetStream backing and so
// cannot be redelivered on resume. Keeping them would leak a Receive Maximum
// slot for the life of a persistent session.
//
// Lock held on entry
func (sess *mqttSession) dropUnredeliverableRetained() {
	for pi, ack := range sess.pendingPublish {
		if ack.jsAckSubject == _EMPTY_ {
			delete(sess.pendingPublish, pi)
		}
	}
}

// trackPublishRetained is invoked when a retained (QoS) message is published. It
// allocates a new PI and adds it to pendingPublish with an empty value (no
// JetStream backing). Spec5 [3.3.4].
//
// Lock held on entry
func (sess *mqttSession) trackPublishRetained() uint16 {
	// Make sure we initialize the tracking maps.
	if sess.pendingPublish == nil {
		sess.pendingPublish = make(map[uint16]*mqttPending)
	}
	if sess.cpending == nil {
		sess.cpending = make(map[string]map[uint64]uint16)
	}

	// Honor the effective in-flight cap (MaxAckPending capped by the client's
	// Receive Maximum). At the limit, return 0 so the caller downgrades this
	// retained message to QoS0: it is still delivered, but does not count as an
	// unacknowledged QoS1/2 PUBLISH. Spec5 [3.3.4].
	if sess.qos12InflightForCap() >= sess.effectiveMaxAck() {
		return 0
	}

	pi := sess.bumpPI()
	if pi == 0 {
		return 0
	}
	sess.pendingPublish[pi] = &mqttPending{}

	return pi
}

// trackPublish is invoked when a (QoS) PUBLISH message is to be delivered. It
// detects an untracked (new) message based on its sequence extracted from its
// delivery-time jsAckSubject, and adds it to the tracking maps. Returns a PI to
// use for the message (new, or previously used), and whether this is a
// duplicate delivery attempt.
//
// Lock held on entry
// The returned started flag is true when the PI was already tracked, i.e. this
// is a redelivery of a message whose onward delivery already began.
func (sess *mqttSession) trackPublish(jsDur, jsAckSubject string) (packetID uint16, dup, started bool) {
	var pi uint16

	if jsAckSubject == _EMPTY_ || jsDur == _EMPTY_ {
		return 0, false, false
	}

	// Make sure we initialize the tracking maps.
	if sess.pendingPublish == nil {
		sess.pendingPublish = make(map[uint16]*mqttPending)
	}
	if sess.cpending == nil {
		sess.cpending = make(map[string]map[uint64]uint16)
	}

	// Get the stream sequence and duplicate flag from the ack reply subject.
	sseq, _, dcount, _, _ := ackReplyInfo(jsAckSubject)
	if dcount > 1 {
		dup = true
	}

	var ack *mqttPending
	sseqToPi, ok := sess.cpending[jsDur]
	if !ok {
		sseqToPi = make(map[uint64]uint16)
		sess.cpending[jsDur] = sseqToPi
	} else {
		pi = sseqToPi[sseq]
	}

	if pi != 0 {
		// There is a possible race between a PUBLISH re-delivery calling us,
		// and a PUBREC received already having submitting a PUBREL into JS . If
		// so, indicate no need for (re-)delivery by returning a PI of 0.
		_, usedForPubRel := sess.pendingPubRel[pi]
		if /*dup && */ usedForPubRel {
			return 0, false, false
		}

		// We should have a pending JS ACK for this PI. This is a redelivery of a
		// message already counted against the in-flight cap, so it is not gated
		// again here. NOTE: if a persistent session accumulated more unacked
		// messages than a newly-lowered Receive Maximum, redeliveries of those
		// pre-existing pending messages are not additionally paced on the new
		// connection (a known limitation; new deliveries below still are, and
		// the session drains to the cap as PUBACKs arrive).
		ack = sess.pendingPublish[pi]
		started = true
	} else {
		// Gate new deliveries at the effective cap: MaxAckPending capped by the
		// client's MQTT 5.0 Receive Maximum. QoS 2 messages awaiting PUBCOMP are
		// counted too when a Receive Maximum applies (Spec5 [4.9]).
		if sess.qos12InflightForCap() >= sess.effectiveMaxAck() {
			// Indicate that we did not assign a packet identifier.
			// The caller will not send the message to the subscription
			// and JS will redeliver later, based on consumer's AckWait.
			return 0, false, false
		}

		pi = sess.bumpPI()
		if pi == 0 {
			return 0, false, false
		}

		sseqToPi[sseq] = pi
	}

	if ack == nil {
		sess.pendingPublish[pi] = &mqttPending{
			jsDur:        jsDur,
			sseq:         sseq,
			jsAckSubject: jsAckSubject,
		}
	} else {
		ack.jsAckSubject = jsAckSubject
		ack.sseq = sseq
		ack.jsDur = jsDur
	}

	return pi, dup, started
}

// Stops a PI from being tracked as a PUBLISH. It can still be in use for a
// pending PUBREL.
//
// Lock held on entry
func (sess *mqttSession) untrackPublish(pi uint16) (jsAckSubject string) {
	ack, ok := sess.pendingPublish[pi]
	if !ok {
		return _EMPTY_
	}

	delete(sess.pendingPublish, pi)
	if len(sess.pendingPublish) == 0 {
		sess.last_pi = 0
	}

	if len(sess.cpending) != 0 && ack.jsDur != _EMPTY_ {
		if sseqToPi := sess.cpending[ack.jsDur]; sseqToPi != nil {
			delete(sseqToPi, ack.sseq)
		}
	}

	return ack.jsAckSubject
}

// trackAsPubRel is invoked in 2 cases: (a) when we receive a PUBREC and we need
// to change from tracking the PI as a PUBLISH to a PUBREL; and (b) when we
// attempt to deliver the PUBREL to record the JS ack subject for it.
//
// Lock held on entry
func (sess *mqttSession) trackAsPubRel(pi uint16, jsAckSubject string) {
	if sess.pubRelConsumer == nil {
		// The cosumer MUST be set up already.
		return
	}
	jsDur := sess.pubRelConsumer.Durable

	if sess.pendingPubRel == nil {
		sess.pendingPubRel = make(map[uint16]*mqttPending)
	}

	if jsAckSubject == _EMPTY_ {
		sess.pendingPubRel[pi] = &mqttPending{
			jsDur: jsDur,
		}
		return
	}

	sseq, _, _, _, _ := ackReplyInfo(jsAckSubject)

	if sess.cpending == nil {
		sess.cpending = make(map[string]map[uint64]uint16)
	}
	sseqToPi := sess.cpending[jsDur]
	if sseqToPi == nil {
		sseqToPi = make(map[uint64]uint16)
		sess.cpending[jsDur] = sseqToPi
	}
	sseqToPi[sseq] = pi
	sess.pendingPubRel[pi] = &mqttPending{
		jsDur:        sess.pubRelConsumer.Durable,
		sseq:         sseq,
		jsAckSubject: jsAckSubject,
	}
}

// Stops a PI from being tracked as a PUBREL.
//
// Lock held on entry
func (sess *mqttSession) untrackPubRel(pi uint16) (jsAckSubject string) {
	ack, ok := sess.pendingPubRel[pi]
	if !ok {
		return _EMPTY_
	}

	delete(sess.pendingPubRel, pi)

	if sess.pubRelConsumer != nil && len(sess.cpending) > 0 {
		if sseqToPi := sess.cpending[ack.jsDur]; sseqToPi != nil {
			delete(sseqToPi, ack.sseq)
		}
	}

	return ack.jsAckSubject
}

// Sends a consumer delete request, but does not wait for response.
//
// Lock not held on entry.
func (sess *mqttSession) deleteConsumer(cc *ConsumerConfig) {
	sess.mu.Lock()
	sess.tmaxack -= cc.MaxAckPending
	sess.jsa.deleteConsumer(mqttStreamName, cc.Durable, true)
	sess.mu.Unlock()
}

//////////////////////////////////////////////////////////////////////////////
//
// CONNECT protocol related functions
//
//////////////////////////////////////////////////////////////////////////////

// Parse the MQTT connect protocol
func (c *client) mqttParseConnect(r *mqttReader, hasMappings bool) (byte, *mqttConnectProto, error) {
	// Protocol name
	proto, err := r.readBytes("protocol name", false)
	if err != nil {
		return 0, nil, err
	}

	// Spec [MQTT-3.1.2-1]
	if !bytes.Equal(proto, mqttProtoName) {
		// Check proto name against v3.1 to report better error
		if bytes.Equal(proto, mqttOldProtoName) {
			return 0, nil, fmt.Errorf("older protocol %q not supported", proto)
		}
		return 0, nil, fmt.Errorf("expected connect packet with protocol name %q, got %q", mqttProtoName, proto)
	}

	// Protocol level
	level, err := r.readByte("protocol level")
	if err != nil {
		return 0, nil, err
	}
	// Spec [MQTT-3.1.2-2], spec5 [3.1.2.2]. We support 3.1.1 (0x4) and 5.0 (0x5).
	switch level {
	case mqttProtoLevel, mqttProtoLevel5:
	default:
		return mqttConnAckRCUnacceptableProtocolVersion, nil, fmt.Errorf("unacceptable protocol version of %v", level)
	}
	// Enforce the maximum accepted protocol version. MQTT 5.0 support is still
	// being completed (e.g. session/message/will-delay expiry are not yet
	// honored), so it is opt-in: unless the operator sets MaxProtocolVersion to
	// 5, the server accepts only 3.1.1. When rejecting, reply using the framing
	// the client asked for (set c.mqtt.proto) so it can read the reason code and
	// fall back.
	if c.srv != nil {
		maxv := c.srv.getOpts().MQTT.MaxProtocolVersion
		if maxv == 0 {
			maxv = mqttProtoLevel
		}
		if level > maxv {
			c.mqtt.proto = level
			return mqttConnAckRCUnacceptableProtocolVersion, nil, fmt.Errorf("MQTT protocol version %v not accepted (maximum is %v); set mqtt.max_protocol_version to 5 to enable MQTT 5.0", level, maxv)
		}
	}
	// Record the negotiated version; it drives wire framing for the rest of the
	// connection's lifetime (CONNACK, ACKs, DISCONNECT).
	c.mqtt.proto = level

	cp := &mqttConnectProto{}
	// Connect flags
	cp.flags, err = r.readByte("flags")
	if err != nil {
		return 0, nil, err
	}

	// Spec [MQTT-3.1.2-3]
	if cp.flags&mqttConnFlagReserved != 0 {
		return 0, nil, errMQTTConnFlagReserved
	}

	var hasWill bool
	wqos := (cp.flags & mqttConnFlagWillQoS) >> 3
	wretain := cp.flags&mqttConnFlagWillRetain != 0
	// Spec [MQTT-3.1.2-11]
	if cp.flags&mqttConnFlagWillFlag == 0 {
		// Spec [MQTT-3.1.2-13]
		if wqos != 0 {
			return 0, nil, fmt.Errorf("if Will flag is set to 0, Will QoS must be 0 too, got %v", wqos)
		}
		// Spec [MQTT-3.1.2-15]
		if wretain {
			return 0, nil, errMQTTWillAndRetainFlag
		}
	} else {
		// Spec [MQTT-3.1.2-14]
		if wqos == 3 {
			return 0, nil, fmt.Errorf("if Will flag is set to 1, Will QoS can be 0, 1 or 2, got %v", wqos)
		}
		hasWill = true
	}

	if c.mqtt.rejectQoS2Pub && hasWill && wqos == 2 {
		return mqttConnAckRCQoS2WillRejected, nil, fmt.Errorf("server does not accept QoS2 for Will messages")
	}

	// Spec [MQTT-3.1.2-19]
	hasUser := cp.flags&mqttConnFlagUsernameFlag != 0
	// Spec [MQTT-3.1.2-21]
	hasPassword := cp.flags&mqttConnFlagPasswordFlag != 0
	// Spec [MQTT-3.1.2-22]
	if !hasUser && hasPassword {
		return 0, nil, errMQTTPasswordFlagAndNoUser
	}

	// Keep alive
	var ka uint16
	ka, err = r.readUint16("keep alive")
	if err != nil {
		return 0, nil, err
	}
	// Spec [MQTT-3.1.2-24]
	if ka > 0 {
		cp.rd = time.Duration(float64(ka)*1.5) * time.Second
	}

	// MQTT 5.0: the CONNECT variable header ends with a properties block, just
	// before the payload. Spec5 [3.1.2.11].
	if level == mqttProtoLevel5 {
		cp.props, err = r.readProperties(mqttPacketConnect)
		if err != nil {
			return 0, nil, err
		}
		// Enhanced authentication (AUTH exchange) is not implemented. If the
		// client requests an authentication method, reject the connection with
		// the v5 "bad authentication method" reason. Spec5 [4.12].
		if cp.props != nil && cp.props.authMethod != _EMPTY_ {
			return mqttReasonBadAuthMethod, nil, errMQTTAuthMethodNotSupported
		}
		// Spec5 [3.1.2.11.10]: Authentication Data without an Authentication
		// Method is a Protocol Error.
		if cp.props != nil && cp.props.authData != nil && cp.props.authMethod == _EMPTY_ {
			return mqttReasonProtocolError, nil, fmt.Errorf("%w: authentication data without authentication method", errMQTTProtocolError)
		}
	}

	// Payload starts here and order is mandated by:
	// Spec [MQTT-3.1.3-1]: client ID, will topic, will message, username, password

	// Client ID
	c.mqtt.cid, err = r.readString("client ID")
	if err != nil {
		return 0, nil, err
	}
	// Spec [MQTT-3.1.3-7]
	if c.mqtt.cid == _EMPTY_ {
		if cp.flags&mqttConnFlagCleanSession == 0 {
			return mqttConnAckRCIdentifierRejected, nil, errMQTTCIDEmptyNeedsCleanFlag
		}
		// Spec [MQTT-3.1.3-6]
		c.mqtt.cid = nuid.Next()
		c.mqtt.cidGenerated = true
	}
	// Spec [MQTT-3.1.3-4] and [MQTT-3.1.3-9]
	if err := mqttValidateString(c.mqtt.cid, "client ID"); err != nil {
		return mqttConnAckRCIdentifierRejected, nil, err
	} else if !isValidName(c.mqtt.cid) {
		// Should not contain characters that make it an invalid name for NATS subjects, etc.
		err = fmt.Errorf("invalid character in %s %q", "client ID", c.mqtt.cid)
		return mqttConnAckRCIdentifierRejected, nil, err
	}

	if hasWill {
		cp.will = &mqttWill{
			qos:    wqos,
			retain: wretain,
		}
		// MQTT 5.0: Will properties precede the Will topic. Spec5 [3.1.3.2].
		if level == mqttProtoLevel5 {
			cp.will.props, err = r.readProperties(mqttPropsContextWill)
			if err != nil {
				return 0, nil, err
			}
		}
		var topic []byte
		// Need to make a copy since we need to hold to this topic after the
		// parsing of this protocol.
		topic, err = r.readBytes("Will topic", true)
		if err != nil {
			return 0, nil, err
		}
		if len(topic) == 0 {
			return 0, nil, errMQTTEmptyWillTopic
		}
		if err := mqttValidateTopic(topic, "Will topic"); err != nil {
			return 0, nil, err
		}
		// Convert MQTT topic to NATS subject
		cp.will.subject, err = mqttTopicToNATSPubSubject(topic)
		if err != nil {
			return 0, nil, err
		}
		// Check for subject mapping.
		if hasMappings {
			// For selectMappedSubject to work, we need to have c.pa.subject set.
			// If there is a change, c.pa.mapped will be set after the call.
			c.pa.subject = cp.will.subject
			if changed := c.selectMappedSubject(); changed {
				// We need to keep track of the NATS subject/mapped in the `cp` structure.
				cp.will.subject = c.pa.subject
				cp.will.mapped = c.pa.mapped
				// We also now need to map the original MQTT topic to the new topic
				// based on the new subject.
				topic = natsSubjectToMQTTTopic(cp.will.subject)
			}
			// Reset those now.
			c.pa.subject, c.pa.mapped = nil, nil
		}
		cp.will.topic = topic
		// Now "will" message.
		// Ask for a copy since we need to hold to this after parsing of this protocol.
		cp.will.message, err = r.readBytes("Will message", true)
		if err != nil {
			return 0, nil, err
		}
	}

	if hasUser {
		c.opts.Username, err = r.readString("user name")
		if err != nil {
			return 0, nil, err
		}
		if c.opts.Username == _EMPTY_ {
			return mqttConnAckRCBadUserOrPassword, nil, errMQTTEmptyUsername
		}
		// Spec [MQTT-3.1.3-11]
		if err := mqttValidateString(c.opts.Username, "user name"); err != nil {
			return mqttConnAckRCBadUserOrPassword, nil, err
		}
	}

	if hasPassword {
		c.opts.Password, err = r.readString("password")
		if err != nil {
			return 0, nil, err
		}
		c.opts.Token = c.opts.Password
	}
	return 0, cp, nil
}

func (c *client) mqttConnectTrace(cp *mqttConnectProto) string {
	trace := fmt.Sprintf("clientID=%s", c.mqtt.cid)
	if cp.rd > 0 {
		trace += fmt.Sprintf(" keepAlive=%v", cp.rd)
	}
	if cp.will != nil {
		trace += fmt.Sprintf(" will=(topic=%s QoS=%v retain=%v)",
			cp.will.topic, cp.will.qos, cp.will.retain)
	}
	if cp.flags&mqttConnFlagCleanSession != 0 {
		trace += " clean"
	}
	if c.opts.Username != _EMPTY_ {
		trace += fmt.Sprintf(" username=%s", c.opts.Username)
	}
	if c.opts.Password != _EMPTY_ {
		trace += " password=****"
	}
	return trace
}

// Process the CONNECT packet.
//
// For the first session on the account, an account session manager will be created,
// along with the JetStream streams/consumer necessary for the working of MQTT.
//
// The session, identified by a client ID, will be registered, or if already existing,
// will be resumed. If the session exists but is associated with an existing client,
// the old client is evicted, as per the specifications.
//
// Due to specific locking requirements around JS API requests, we cannot hold some
// locks for the entire duration of processing of some protocols, therefore, we use
// a map that registers the client ID in a "locked" state. If a different client tries
// to connect and the server detects that the client ID is in that map, it will try
// a little bit until it is not, or fail the new client, since we can't protect
// processing of protocols in the original client. This is not expected to happen often.
//
// Runs from the client's readLoop.
// No lock held on entry.
func (s *Server) mqttProcessConnect(c *client, cp *mqttConnectProto, trace bool) error {
	sendConnAck := func(rc byte, sessp bool) {
		c.mqttEnqueueConnAck(rc, sessp)
		if trace {
			c.traceOutOp("CONNACK", []byte(fmt.Sprintf("sp=%v rc=%v", sessp, rc)))
		}
	}

	c.mu.Lock()
	cid := c.mqtt.cid
	c.clearAuthTimer()
	c.mu.Unlock()
	if !s.isClientAuthorized(c) {
		if trace {
			c.traceOutOp("CONNACK", []byte(fmt.Sprintf("sp=%v rc=%v", false, mqttConnAckRCNotAuthorized)))
		}
		c.authViolation()
		return ErrAuthentication
	}
	// Now that we are authenticated, we have the client bound to the account.
	// Get the account's level MQTT sessions manager. If it does not exists yet,
	// this will create it along with the streams where sessions and messages
	// are stored.
	asm, err := s.getOrCreateMQTTAccountSessionManager(c)
	if err != nil {
		return err
	}

	// Most of the session state is altered only in the readLoop so does not
	// need locking. For things that can be access in the readLoop and in
	// callbacks, we will use explicit locking.
	// To prevent other clients to connect with the same client ID, we will
	// add the client ID to a "locked" map so that the connect somewhere else
	// is put on hold.
	// This keep track of how many times this client is detecting that its
	// client ID is in the locked map. After a short amount, the server will
	// fail this inbound client.
	locked := 0

CHECK:
	asm.mu.Lock()
	// Check if different applications keep trying to connect with the same
	// client ID at the same time.
	if tm, ok := asm.flappers[cid]; ok {
		// If the last time it tried to connect was more than 1 sec ago,
		// then accept and remove from flappers map.
		if time.Since(tm) > mqttSessJailDur {
			asm.removeSessFromFlappers(cid)
		} else {
			// Will hold this client for a second and then close it. We
			// do this so that if the client has a reconnect feature we
			// don't end-up with very rapid flapping between apps.
			// We need to wait in place and not schedule the connection
			// close because if this is a misbehaved client that does
			// not wait for the CONNACK and sends other protocols, the
			// server would not have a fully setup client and may panic.
			asm.mu.Unlock()
			select {
			case <-s.quitCh:
			case <-time.After(mqttSessJailDur):
			}
			c.closeConnection(DuplicateClientID)
			return ErrConnectionClosed
		}
	}
	// If an existing session is in the process of processing some packet, we can't
	// evict the old client just yet. So try again to see if the state clears, but
	// if it does not, then we have no choice but to fail the new client instead of
	// the old one.
	if _, ok := asm.sessLocked[cid]; ok {
		asm.mu.Unlock()
		if locked++; locked == 10 {
			return fmt.Errorf("other session with client ID %q is in the process of connecting", cid)
		}
		time.Sleep(100 * time.Millisecond)
		goto CHECK
	}

	// Register this client ID the "locked" map for the duration if this function.
	asm.sessLocked[cid] = struct{}{}
	// And remove it on exit, regardless of error or not.
	defer func() {
		asm.mu.Lock()
		delete(asm.sessLocked, cid)
		asm.mu.Unlock()
	}()

	// Is the client requesting a clean session or not.
	cleanSess := cp.flags&mqttConnFlagCleanSession != 0
	// Session present? Assume false, will be set to true only when applicable.
	sessp := false
	// Do we have an existing session for this client ID
	es, exists := asm.sessions[cid]
	asm.mu.Unlock()
	formatError := func(err error) error {
		return fmt.Errorf("%v for account %q, session %q", err, c.acc.GetName(), cid)
	}

	// The session is not in the map, but may be on disk, so try to recover
	// or create the stream if not.
	if !exists {
		es, exists, err = asm.createOrRestoreSession(cid, s.getOpts())
		if err != nil {
			if err == errMQTTSessionCollision {
				sendConnAck(mqttConnAckRCIdentifierRejected, false)
			}
			return formatError(err)
		}
	}
	if exists {
		// Clear the session if client wants a clean session.
		// Also, Spec [MQTT-3.2.2-1]: don't report session present
		if cleanSess || es.clean {
			// Spec [MQTT-3.1.2-6]: If CleanSession is set to 1, the Client and
			// Server MUST discard any previous Session and start a new one.
			// This Session lasts as long as the Network Connection. State data
			// associated with this Session MUST NOT be reused in any subsequent
			// Session.
			if err := es.clear(false); err != nil {
				asm.removeSession(es, true)
				return err
			}
		} else {
			// Report to the client that the session was present
			sessp = true
		}
		// Spec [MQTT-3.1.4-2]. If the ClientId represents a Client already
		// connected to the Server then the Server MUST disconnect the existing
		// client.
		// Bind with the new client. This needs to be protected because can be
		// accessed outside of the readLoop.
		es.mu.Lock()
		ec := es.c
		es.c = c
		es.clean = cleanSess
		// Clear this flag so we resubscribe to PUBREL subject is needed.
		es.pubRelSubscribed = false
		if sessp {
			// Resumed session: release retained (QoS1/2) deliveries with no
			// JetStream backing. They cannot be redelivered, so keeping them would
			// leak a Receive Maximum slot for the life of the session.
			es.dropUnredeliverableRetained()
		}
		es.mu.Unlock()
		if ec != nil {
			// Remove "will" of existing client before closing
			ec.mu.Lock()
			ec.mqtt.cp.will = nil
			ec.mu.Unlock()
			// Add to the map of the flappers
			asm.mu.Lock()
			asm.addSessToFlappers(cid)
			asm.mu.Unlock()
			c.Warnf("Replacing old client %q since both have the same client ID %q", ec, cid)
			// Tell the evicted v5 client why before the close (no-op for
			// 3.1.1). Spec5 [3.1.4].
			ec.mqttEnqueueDisconnect(mqttReasonSessionTakenOver)
			// Close old client in separate go routine
			go ec.closeConnection(DuplicateClientID)
		}
	} else {
		// Spec [MQTT-3.2.2-3]: if the Server does not have stored Session state,
		// it MUST set Session Present to 0 in the CONNACK packet.
		es.mu.Lock()
		es.c, es.clean = c, cleanSess
		es.mu.Unlock()
		// Now add this new session into the account sessions
		asm.addSession(es, true)
	}
	// MQTT 5.0 Receive Maximum: cap the number of in-flight unacknowledged
	// QoS1/2 PUBLISH we will send to this client. Re-evaluated on every CONNECT
	// since a resumed session may be taken over by a client with a different
	// (or no) limit. 0 means no client-imposed limit.
	var rmax uint16
	if cp.props != nil {
		rmax = cp.props.receiveMax
	}
	es.mu.Lock()
	es.rmax = rmax
	es.mu.Unlock()

	// MQTT 5.0 Maximum Packet Size: never send this client a PUBLISH larger than
	// it will accept. Unlike Receive Maximum this lands on the per-connection
	// client (not the session): it is read lock-free on the delivery paths and
	// must gate the QoS0 path, which has no session lock. A fresh client per
	// connection makes it inherently per-connection, so no explicit re-eval is
	// needed. 0 means no client-imposed limit.
	if cp.props != nil {
		c.mqtt.maxPacketSize = cp.props.maxPacketSize
	}

	// We would need to save only if it did not exist previously, but we save
	// always in case we are running in cluster mode. This will notify other
	// running servers that this session is being used.
	if err := es.save(); err != nil {
		asm.removeSession(es, true)
		return err
	}
	c.mu.Lock()
	c.flags.set(connectReceived)
	c.mqtt.cp = cp
	c.mqtt.asm = asm
	c.mqtt.sess = es
	c.mu.Unlock()

	// Spec [MQTT-3.2.0-1]: CONNACK must be the first protocol sent to the session.
	sendConnAck(mqttConnAckRCConnectionAccepted, sessp)

	// Process possible saved subscriptions.
	if l := len(es.subs); l > 0 {
		filters := make([]*mqttFilter, 0, l)
		for subject, qos := range es.subs {
			filters = append(filters, &mqttFilter{filter: subject, qos: qos})
		}
		if _, err := asm.processSubs(es, c, filters, false, trace); err != nil {
			return err
		}
	}
	return nil
}

// mqttConnAckReasonFromRC maps a 3.1.1 CONNACK return code to the equivalent
// MQTT 5.0 reason code. Codes already in the v5 failure range (>= 0x80) are
// passed through, which lets callers inject v5-only reasons (e.g. bad auth
// method) without a 3.1.1 equivalent. Spec5 [3.2.2.2].
func mqttConnAckReasonFromRC(rc byte) byte {
	switch rc {
	case mqttConnAckRCConnectionAccepted:
		return mqttReasonSuccess
	case mqttConnAckRCUnacceptableProtocolVersion:
		return mqttReasonUnsupportedProtocolVersion
	case mqttConnAckRCIdentifierRejected:
		return mqttReasonClientIDNotValid
	case mqttConnAckRCServerUnavailable:
		return mqttReasonServerUnavailable
	case mqttConnAckRCBadUserOrPassword:
		return mqttReasonBadUserOrPassword
	case mqttConnAckRCNotAuthorized:
		return mqttReasonNotAuthorized
	case mqttConnAckRCQoS2WillRejected:
		return mqttReasonQoSNotSupported
	}
	if rc >= 0x80 {
		return rc
	}
	return mqttReasonUnspecifiedError
}

func (c *client) mqttEnqueueConnAck(rc byte, sessionPresent bool) {
	// Spec [MQTT-3.2.2-4], spec5 [3.2.2.1.1]: when the (reason) code indicates
	// failure, the session present flag must be 0.
	sp := byte(0)
	if rc == 0 && sessionPresent {
		sp = 1
	}

	if c.mqtt.proto == mqttProtoLevel5 {
		c.mqttEnqueueConnAckV5(rc, sp)
		return
	}

	proto := [4]byte{mqttPacketConnectAck, 2, sp, rc}
	c.mu.Lock()
	c.enqueueProto(proto[:])
	c.mu.Unlock()
}

// mqttEnqueueConnAckV5 writes an MQTT 5.0 CONNACK: a reason code, the session
// present flag, and a properties block advertising the server's capabilities.
func (c *client) mqttEnqueueConnAckV5(rc, sp byte) {
	reason := mqttConnAckReasonFromRC(rc)

	props := &mqttProperties{present: map[byte]bool{}}
	// Advertise the capabilities of the current implementation. Properties left
	// absent take their spec defaults, which already describe us correctly, so
	// we MUST NOT send them with an explicit value:
	//   - Maximum QoS: absent => QoS 2 supported. (A value of 2 is illegal in
	//     this property: spec5 [3.2.2.3.4] allows only 0 or 1.)
	//   - Retain Available: absent => retained messages supported.
	//   - Wildcard Subscription Available: absent => wildcards supported.
	//   - Topic Alias Maximum: absent => 0, i.e. we accept no topic aliases.
	// We only emit the properties whose truthful value differs from the default.
	// Shared subscriptions and subscription identifiers are not implemented by
	// this foundation, so advertise them as unavailable. Spec5 [3.2.2.3].
	props.sharedSubAvail = 0
	props.present[mqttPropSharedSubAvailable] = true
	props.subIDAvail = 0
	props.present[mqttPropSubIDAvailable] = true
	// We intentionally do NOT advertise Maximum Packet Size. The natural
	// candidate (Options.MaxPayload) is not the value the server actually
	// enforces: an inbound PUBLISH is re-encoded as a NATS message with extra
	// header overhead and checked against MaxPayload (see mqttComputeNatsMsgSize),
	// so a v5 PUBLISH sized just under MaxPayload can still be rejected.
	// Advertising a limit the server does not honor is worse than advertising
	// none (absent => the client applies no server-side limit, same as 3.1.1),
	// so we omit it until packet-size enforcement is implemented.
	// Echo a server-assigned client identifier. Spec5 [3.2.2.3.7].
	if reason == mqttReasonSuccess && c.mqtt.cidGenerated {
		props.assignedClientID = c.mqtt.cid
	}

	w := newMQTTWriter(0)
	w.WriteByte(mqttPacketConnectAck)
	// Variable header = session present (1) + reason code (1) + properties.
	var vh mqttWriter
	vh.WriteByte(sp)
	vh.WriteByte(reason)
	vh.writeProperties(props)
	w.WriteVarInt(vh.Len())
	w.Write(vh.Bytes())

	c.mu.Lock()
	c.enqueueProto(w.Bytes())
	c.mu.Unlock()
}

// mqttEnqueueDisconnect sends an MQTT 5.0 DISCONNECT with the given reason code
// (no properties) to the client, before the connection is closed on a
// protocol/processing error. It is a no-op for 3.1.1 connections, which have
// no server-initiated DISCONNECT. Spec5 [3.14].
func (c *client) mqttEnqueueDisconnect(reason byte) {
	if c.mqtt == nil || c.mqtt.proto != mqttProtoLevel5 {
		return
	}
	// Remaining length of 1: just the reason code, properties omitted (allowed
	// when there are no properties). Spec5 [3.14.2.2.1].
	proto := [3]byte{mqttPacketDisconnect, 1, reason}
	c.mu.Lock()
	c.enqueueProto(proto[:])
	c.mu.Unlock()
}

// mqttDisconnectReasonFromErr picks a v5 DISCONNECT reason code for a parse or
// processing error. Spec5 [3.14.2.1].
func mqttDisconnectReasonFromErr(err error) byte {
	switch {
	case errors.Is(err, errMQTTMalformedVarInt), errors.Is(err, errMQTTMalformedProperties):
		return mqttReasonMalformedPacket
	case errors.Is(err, errMQTTUnknownProperty), errors.Is(err, errMQTTPropertyNotAllowed),
		errors.Is(err, errMQTTDuplicateProperty), errors.Is(err, errMQTTProtocolError):
		return mqttReasonProtocolError
	}
	return mqttReasonUnspecifiedError
}

// mqttConnAckReasonFromConnectErr picks a v5 CONNACK reason code for a CONNECT
// that failed to parse without a return code: property errors are Protocol
// Error (0x82), everything else Malformed Packet (0x81). Spec5 [3.1.4.1].
func mqttConnAckReasonFromConnectErr(err error) byte {
	switch {
	case errors.Is(err, errMQTTUnknownProperty), errors.Is(err, errMQTTPropertyNotAllowed),
		errors.Is(err, errMQTTDuplicateProperty), errors.Is(err, errMQTTProtocolError):
		return mqttReasonProtocolError
	}
	return mqttReasonMalformedPacket
}

func (s *Server) mqttHandleWill(c *client) {
	c.mu.Lock()
	if c.mqtt.cp == nil {
		c.mu.Unlock()
		return
	}
	will := c.mqtt.cp.will
	if will == nil {
		c.mu.Unlock()
		return
	}
	pp := c.mqtt.pp
	pp.topic = will.topic
	pp.subject = will.subject
	pp.mapped = will.mapped
	pp.msg = will.message
	pp.sz = len(will.message)
	pp.pi = 0
	pp.flags = will.qos << 1
	if will.retain {
		pp.flags |= mqttPubFlagRetain
	}
	// pp is the shared publish struct; replace any properties left over from
	// the client's last PUBLISH with the Will's own. Spec5 [3.1.3.2].
	pp.props = mqttWillForwardProps(will.props)
	c.mu.Unlock()
	s.mqttInitiateMsgDelivery(c, pp)
	c.flushClients(0)
}

// mqttWillForwardProps encodes a Will's properties as the raw block (length
// prefix + body, the pp.props format) to attach to the Will PUBLISH. Will Delay
// Interval is consumed by the server and has no encode case, so it is never
// forwarded. Spec5 [3.1.3.2].
func mqttWillForwardProps(p *mqttProperties) []byte {
	if p == nil {
		return nil
	}
	w := newMQTTWriter(0)
	w.writeProperties(p)
	// Just the zero-length varint: nothing to forward.
	if w.Len() <= 1 {
		return nil
	}
	return w.Bytes()
}

//////////////////////////////////////////////////////////////////////////////
//
// PUBLISH protocol related functions
//
//////////////////////////////////////////////////////////////////////////////

func (c *client) mqttParsePub(r *mqttReader, pl int, pp *mqttPublish, hasMappings bool) error {
	qos := mqttGetQoS(pp.flags)
	if qos > 2 {
		return fmt.Errorf("QoS=%v is invalid in MQTT", qos)
	}

	if c.mqtt.rejectQoS2Pub && qos == 2 {
		return fmt.Errorf("QoS=2 is disabled for PUBLISH messages")
	}

	// Keep track of where we are when starting to read the variable header
	start := r.pos

	var err error
	pp.topic, err = r.readBytes("topic", false)
	if err != nil {
		return err
	}
	if len(pp.topic) == 0 {
		return errMQTTTopicIsEmpty
	}
	if err := mqttValidateTopic(pp.topic, "topic"); err != nil {
		return err
	}
	// Convert the topic to a NATS subject. This call will also check that
	// there is no MQTT wildcards (Spec [MQTT-3.3.2-2] and [MQTT-4.7.1-1])
	// Note that this may not result in a copy if there is no conversion.
	// It is good because after the message is processed we won't have a
	// reference to the buffer and we save a copy.
	pp.subject, err = mqttTopicToNATSPubSubject(pp.topic)
	if err != nil {
		return err
	}

	// Check for subject mapping.
	if hasMappings {
		// For selectMappedSubject to work, we need to have c.pa.subject set.
		// If there is a change, c.pa.mapped will be set after the call.
		c.pa.subject = pp.subject
		if changed := c.selectMappedSubject(); changed {
			// We need to keep track of the NATS subject/mapped in the `pp` structure.
			pp.subject = c.pa.subject
			pp.mapped = c.pa.mapped
			// We also now need to map the original MQTT topic to the new topic
			// based on the new subject.
			pp.topic = natsSubjectToMQTTTopic(pp.subject)
		}
		// Reset those now.
		c.pa.subject, c.pa.mapped = nil, nil
	}

	if qos > 0 {
		pp.pi, err = r.readUint16("packet identifier")
		if err != nil {
			return err
		}
		if pp.pi == 0 {
			return fmt.Errorf("with QoS=%v, packet identifier cannot be 0", qos)
		}
	} else {
		pp.pi = 0
	}

	// MQTT 5.0: PUBLISH properties follow the packet identifier (or topic, for
	// QoS 0) and precede the payload. Spec5 [3.3.2.3]. We parse/validate them
	// but do not act on them yet (foundation). Reading here also advances the
	// reader so the payload-size computation below is correct.
	if c.mqtt.proto == mqttProtoLevel5 {
		// Capture the raw properties block (length prefix + body) so it can be
		// forwarded verbatim to v5 subscribers. An inbound client PUBLISH can
		// only carry forwardable properties (Topic Alias is rejected below;
		// Subscription Identifier is server->client only), so verbatim re-emit
		// is spec-correct. Spec5 [3.3.2.3].
		propStart := r.pos
		props, perr := r.readProperties(mqttPacketPub)
		if perr != nil {
			return perr
		}
		// Topic aliases are not implemented; we advertise TopicAliasMaximum=0
		// in CONNACK, so a compliant client never sends one. Reject any alias
		// rather than risk mis-delivery. Spec5 [3.3.2.3.4].
		if props != nil && props.present[mqttPropTopicAlias] {
			return fmt.Errorf("MQTT topic alias is not supported")
		}
		// Keep the block only if it carries something (more than the single
		// zero length byte). Copy: the reader buffer is transient.
		if raw := r.buf[propStart:r.pos]; len(raw) > 1 {
			pp.props = copyBytes(raw)
		} else {
			pp.props = nil
		}
	}

	// The message payload will be the total packet length minus
	// what we have consumed for the variable header
	payloadSize := pl - (r.pos - start)
	if payloadSize < 0 {
		return fmt.Errorf("invalid remaining length %d for PUBLISH packet", pl)
	}
	pp.sz = payloadSize
	if pp.sz > 0 {
		start = r.pos
		r.pos += pp.sz
		pp.msg = r.buf[start:r.pos]
	} else if pp.sz == 0 {
		pp.msg = nil
	} else {
		return errMQTTInvalidPublishLength
	}
	return nil
}

func mqttValidateTopic(topic []byte, field string) error {
	if !utf8.Valid(topic) {
		return fmt.Errorf("invalid utf8 for %s %q", field, topic)
	}
	if bytes.IndexByte(topic, 0) >= 0 {
		return fmt.Errorf("invalid null character in %s %q", field, topic)
	}
	return nil
}

func mqttValidateString(value string, field string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("invalid utf8 for %s %q", field, value)
	}
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("invalid null character in %s %q", field, value)
	}
	return nil
}

func mqttPubTrace(pp *mqttPublish) string {
	dup := pp.flags&mqttPubFlagDup != 0
	qos := mqttGetQoS(pp.flags)
	retain := mqttIsRetained(pp.flags)
	var piStr string
	if pp.pi > 0 {
		piStr = fmt.Sprintf(" pi=%v", pp.pi)
	}
	return fmt.Sprintf("%s dup=%v QoS=%v retain=%v size=%v%s",
		pp.topic, dup, qos, retain, pp.sz, piStr)
}

// mqttComputeNatsMsgSize computes the size the NATS message to be delivered
// based on a MQTT PUBLISH packet.
// encodePP: whether to encode complete MQTT PUBLISH packet header information
//   - false: initial delivery (QoS 0/1) needs only base header
//   - true: QoS2 storage needs to encode Nmqtt-Subject and Nmqtt-Mapped
func mqttComputeNatsMsgSize(pp *mqttPublish, encodePP bool, ttl uint32) int {
	size := len(hdrLine) +
		len(mqttNatsHeader) + 2 + 2 + // 2 for ':<qos>', and 2 for CRLF
		2 + // end-of-header CRLF
		pp.sz
	if encodePP {
		size += len(mqttNatsHeaderSubject) + 1 + // +1 for ':'
			len(pp.subject) + 2 // 2 for CRLF

		if len(pp.mapped) > 0 {
			size += len(mqttNatsHeaderMapped) + 1 + // +1 for ':'
				len(pp.mapped) + 2 // 2 for CRLF
		}
	}
	// MQTT 5.0 properties are carried (base64) so they can be forwarded to v5
	// subscribers. Independent of encodePP: needed for both delivery and storage.
	if len(pp.props) > 0 {
		size += len(mqttNatsHeaderProps) + 1 + // +1 for ':'
			base64.StdEncoding.EncodedLen(len(pp.props)) + 2 // 2 for CRLF
	}
	// MQTT 5.0 Message Expiry Interval maps to a JetStream per-message TTL so the
	// stored copy is dropped once its lifetime elapses. Spec5 [3.3.2.3.3].
	if ttl > 0 {
		size += len(JSMessageTTL) + 1 + // +1 for ':'
			len(strconv.FormatUint(uint64(ttl), 10)) + 1 + 2 // +1 for 's', 2 for CRLF
	}
	return size
}

// Composes a NATS message from a MQTT PUBLISH packet. The message includes an
// internal header containint the original packet's QoS, and for QoS2 packets
// the original subject.
//
// Example (QoS2, subject: "foo.bar"):
//
//	NATS/1.0\r\n
//	Nmqtt-Pub:2foo.bar\r\n
//	\r\n
func mqttNewDeliverableMessage(pp *mqttPublish, encodePP bool, ttl uint32) (natsMsg []byte, headerLen int) {
	size := mqttComputeNatsMsgSize(pp, encodePP, ttl)

	buf := bytes.NewBuffer(make([]byte, 0, size))

	qos := mqttGetQoS(pp.flags)

	buf.WriteString(hdrLine)
	buf.WriteString(mqttNatsHeader)
	buf.WriteByte(':')
	buf.WriteByte(qos + '0')
	buf.WriteString(_CRLF_)

	if encodePP {
		buf.WriteString(mqttNatsHeaderSubject)
		buf.WriteByte(':')
		buf.Write(pp.subject)
		buf.WriteString(_CRLF_)

		if len(pp.mapped) > 0 {
			buf.WriteString(mqttNatsHeaderMapped)
			buf.WriteByte(':')
			buf.Write(pp.mapped)
			buf.WriteString(_CRLF_)
		}
	}

	if len(pp.props) > 0 {
		buf.WriteString(mqttNatsHeaderProps)
		buf.WriteByte(':')
		buf.WriteString(base64.StdEncoding.EncodeToString(pp.props))
		buf.WriteString(_CRLF_)
	}

	// MQTT 5.0 Message Expiry Interval: attach a JetStream per-message TTL so the
	// stored copy expires after the requested lifetime. This is server-internal
	// metadata (not one of the forwarded Nmqtt-* headers). Spec5 [3.3.2.3.3].
	if ttl > 0 {
		buf.WriteString(JSMessageTTL)
		buf.WriteByte(':')
		buf.WriteString(strconv.FormatUint(uint64(ttl), 10))
		buf.WriteByte('s')
		buf.WriteString(_CRLF_)
	}

	// End of header
	buf.WriteString(_CRLF_)

	headerLen = buf.Len()

	buf.Write(pp.msg)
	return buf.Bytes(), headerLen
}

// Composes a NATS message for a pending PUBREL packet. The message includes an
// internal header containing the PI for PUBREL/PUBCOMP.
//
// Example (PI:123):
//
//		NATS/1.0\r\n
//	 	Nmqtt-PubRel:123\r\n
//		\r\n
func mqttNewDeliverablePubRel(pi uint16) (natsMsg []byte, headerLen int) {
	size := len(hdrLine) +
		len(mqttNatsPubRelHeader) + 6 + 2 + // 6 for ':65535', and 2 for CRLF
		2 // end-of-header CRLF
	buf := bytes.NewBuffer(make([]byte, 0, size))
	buf.WriteString(hdrLine)
	buf.WriteString(mqttNatsPubRelHeader)
	buf.WriteByte(':')
	buf.WriteString(strconv.FormatInt(int64(pi), 10))
	buf.WriteString(_CRLF_)
	buf.WriteString(_CRLF_)
	return buf.Bytes(), buf.Len()
}

// Process the PUBLISH packet.
//
// Runs from the client's readLoop.
// No lock held on entry.
func (s *Server) mqttProcessPub(c *client, pp *mqttPublish, trace bool) error {
	qos := mqttGetQoS(pp.flags)

	// Enforce max_payload using existing client max payload logic (mpay) by
	// checking the largest NATS message size that would be processed, including
	// the Nats-TTL header that a Message Expiry Interval adds to the stored
	// message. QoS2 is first held with the PUBLISH subject headers (no TTL) and
	// later delivered with the TTL header (no subject headers); the two header
	// sets never coexist, so we compare the two actual forms rather than sum them.
	if maxPayload := atomic.LoadInt32(&c.mpay); maxPayload != jwt.NoLimit {
		total := mqttComputeNatsMsgSize(pp, false, c.mqttStoredMsgTTL(pp))
		if qos == 2 {
			if hold := mqttComputeNatsMsgSize(pp, true, 0); hold > total {
				total = hold
			}
		}
		if total > int(maxPayload) {
			c.maxPayloadViolation(total, maxPayload)
			return ErrMaxPayload
		}
	}

	switch qos {
	case 0:
		return s.mqttInitiateMsgDelivery(c, pp)

	case 1:
		// [MQTT-4.3.2-2]. Initiate onward delivery of the Application Message,
		// Send PUBACK.
		//
		// The receiver is not required to complete delivery of the Application
		// Message before sending the PUBACK. When its original sender receives
		// the PUBACK packet, ownership of the Application Message is
		// transferred to the receiver.
		err := s.mqttInitiateMsgDelivery(c, pp)
		if err == nil {
			c.mqttEnqueuePubResponse(mqttPacketPubAck, pp.pi, trace)
		}
		return err

	case 2:
		// [MQTT-4.3.3-2]. Method A, Store message, send PUBREC.
		//
		// The receiver is not required to complete delivery of the Application
		// Message before sending the PUBREC or PUBCOMP. When its original
		// sender receives the PUBREC packet, ownership of the Application
		// Message is transferred to the receiver.
		err := s.mqttStoreQoS2MsgOnce(c, pp)
		if err == nil {
			c.mqttEnqueuePubResponse(mqttPacketPubRec, pp.pi, trace)
		}
		return err

	default:
		return fmt.Errorf("unreachable: invalid QoS in mqttProcessPub: %v", qos)
	}
}

// mqttStoredMsgTTL returns the JetStream per-message TTL to attach to pp's
// stored copy: its MQTT 5.0 Message Expiry Interval, or 0 in degraded mode
// (the messages stream refused AllowMsgTTL and would reject the header).
func (c *client) mqttStoredMsgTTL(pp *mqttPublish) uint32 {
	if asm := c.mqtt.asm; asm != nil && asm.msgsStreamNoTTL {
		return 0
	}
	return mqttMessageExpiryTTL(pp.props)
}

func (s *Server) mqttInitiateMsgDelivery(c *client, pp *mqttPublish) error {
	// A stored (QoS 1/2) PUBLISH carrying an MQTT 5.0 Message Expiry Interval is
	// given a matching JetStream per-message TTL so it is dropped from the
	// delivery stream once its lifetime elapses. Spec5 [3.3.2.3.3]. Degraded
	// mode drops the header; delivery-side expiry checks still apply.
	natsMsg, headerLen := mqttNewDeliverableMessage(pp, false, c.mqttStoredMsgTTL(pp))

	// Set the client's pubarg for processing.
	c.pa.subject = pp.subject
	c.pa.mapped = pp.mapped
	c.pa.reply = nil
	c.pa.hdr = headerLen
	c.pa.hdb = []byte(strconv.FormatInt(int64(c.pa.hdr), 10))
	c.pa.size = len(natsMsg)
	c.pa.szb = []byte(strconv.FormatInt(int64(c.pa.size), 10))
	defer func() {
		c.pa.subject = nil
		c.pa.mapped = nil
		c.pa.reply = nil
		c.pa.hdr = -1
		c.pa.hdb = nil
		c.pa.size = 0
		c.pa.szb = nil
	}()

	_, permIssue := c.processInboundClientMsg(natsMsg)
	if permIssue {
		return nil
	}

	// If QoS 0 messages don't need to be stored, other (1 and 2) do. Store them
	// JetStream under "$MQTT.msgs.<delivery-subject>"
	if qos := mqttGetQoS(pp.flags); qos == 0 {
		return nil
	}

	// We need to call flushClients now since this we may have called c.addToPCD
	// with destination clients (possibly a route). Without calling flushClients
	// the following call may then be stuck waiting for a reply that may never
	// come because the destination is not flushed (due to c.out.fsp > 0,
	// see addToPCD and writeLoop for details).
	c.flushClients(0)

	_, err := c.mqtt.sess.jsa.storeMsg(mqttStreamSubjectPrefix+string(c.pa.subject), headerLen, natsMsg)

	return err
}

var mqttMaxMsgErrPattern = fmt.Sprintf("%s (%v)", ErrMaxMsgsPerSubject.Error(), JSStreamStoreFailedF)

func (s *Server) mqttStoreQoS2MsgOnce(c *client, pp *mqttPublish) error {
	// `true` means encode the MQTT PUBLISH packet in the NATS message header. No
	// TTL here: this is the QoS2 dedup hold stream (no AllowMsgTTL); the expiry
	// TTL is applied when the message is moved to the delivery stream on PUBREL.
	natsMsg, headerLen := mqttNewDeliverableMessage(pp, true, 0)

	// Do not broadcast the message until it has been deduplicated and released
	// by the sender. Instead store this QoS2 message as
	// "$MQTT.qos2.<client-id>.<PI>". If the message is a duplicate, we get back
	// a ErrMaxMsgsPerSubject, otherwise it does not change the flow, still need
	// to send a PUBREC back to the client. The original subject (translated
	// from MQTT topic) is included in the NATS header of the stored message to
	// use for latter delivery.
	_, err := c.mqtt.sess.jsa.storeMsg(c.mqttQoS2InternalSubject(pp.pi), headerLen, natsMsg)

	// TODO: would prefer a more robust and performant way of checking the
	// error, but it comes back wrapped as an API result.
	if err != nil &&
		(isErrorOtherThan(err, JSStreamStoreFailedF) || err.Error() != mqttMaxMsgErrPattern) {
		return err
	}

	return nil
}

func (c *client) mqttQoS2InternalSubject(pi uint16) string {
	return mqttQoS2IncomingMsgsStreamSubjectPrefix + c.mqtt.cid + "." + strconv.FormatUint(uint64(pi), 10)
}

// Process a PUBREL packet (QoS2, acting as Receiver).
//
// Runs from the client's readLoop.
// No lock held on entry.
func (s *Server) mqttProcessPubRel(c *client, pi uint16, trace bool) error {
	// Once done with the processing, send a PUBCOMP back to the client.
	reason := mqttReasonSuccess
	defer func() { c.mqttEnqueuePubResponseReason(mqttPacketPubComp, pi, reason, trace) }()

	// See if there is a message pending for this pi. All failures are treated
	// as "not found".
	asm := c.mqtt.asm
	stored, _ := asm.jsa.loadLastMsgFor(mqttQoS2IncomingMsgsStreamName, c.mqttQoS2InternalSubject(pi))

	if stored == nil {
		// No message found: no session state for this PI, which a v5 PUBCOMP
		// reports as 0x92. Spec5 [MQTT-4.3.3-1].
		reason = mqttReasonPacketIDNotFound
		return nil
	}
	// Best attempt to delete the message from the QoS2 stream.
	asm.jsa.deleteMsg(mqttQoS2IncomingMsgsStreamName, stored.Sequence, true)

	// only MQTT QoS2 messages should be here, and they must have a subject.
	h := mqttParsePublishNATSHeader(stored.Header)
	if h == nil || h.qos != 2 || len(h.subject) == 0 {
		return errors.New("invalid message in QoS2 PUBREL stream")
	}

	pp := &mqttPublish{
		topic:   natsSubjectToMQTTTopic(h.subject),
		subject: h.subject,
		mapped:  h.mapped,
		msg:     stored.Data,
		sz:      len(stored.Data),
		pi:      pi,
		flags:   h.qos << 1,
		props:   h.props, // forward v5 properties captured at store time
	}

	// MQTT 5.0 Message Expiry Interval: a QoS2 message ages while it waits in the
	// server for the PUBREL. Measure the interval from the original PUBLISH
	// receipt (the hold-stream store time) rather than restarting it here: age
	// the carried interval by the time already elapsed, and drop the message if
	// it has expired before release. Spec5 [3.3.2.3.3].
	var expired bool
	if pp.props, expired = mqttForwardExpiry(pp.props, stored.Time.UnixNano()); expired {
		return nil
	}

	return s.mqttInitiateMsgDelivery(c, pp)
}

// Invoked when processing an inbound client message. If the "retain" flag is
// set, the message is stored so it can be later resent to (re)starting
// subscriptions that match the subject.
//
// Invoked from the MQTT publisher's readLoop. No client lock is held on entry.
func (c *client) mqttHandlePubRetain() {
	pp := c.mqtt.pp
	retainMQTT := mqttIsRetained(pp.flags)
	isBirth, _, isCertificate := sparkbParseBirthDeathTopic(pp.topic)
	retainSparkbBirth := isBirth && !isCertificate

	// [tck-id-topics-nbirth-mqtt] NBIRTH messages MUST be published with MQTT
	// QoS equal to 0 and retain equal to false.
	//
	// [tck-id-conformance-mqtt-aware-nbirth-mqtt-retain] A Sparkplug Aware MQTT
	// Server MUST make NBIRTH messages available on the topic:
	// $sparkplug/certificates/namespace/group_id/NBIRTH/edge_node_id with the
	// MQTT retain flag set to true.
	if retainMQTT == retainSparkbBirth {
		// (retainSparkbBirth && retainMQTT) : not valid, so ignore altogether.
		// (!retainSparkbBirth && !retainMQTT) : nothing to do.
		return
	}

	asm := c.mqtt.asm
	key := string(pp.subject)

	// Always clear the retain flag to deliver a normal published message.
	defer func() {
		pp.flags &= ^mqttPubFlagRetain
	}()

	// Spec [MQTT-3.3.1-11]. Payload of size 0 removes the retained message, but
	// should still be delivered as a normal message.
	//
	// We used to delete the message here from our map, the stream, and notify
	// the network about the delete. We no longer do that. Instead, we store
	// the message with an empty body. When servers will get the empty body
	// in processRetainedMsg, then will remove the message from their map. This
	// effectively serializes all add/remove of retained messages without the
	// need for "network" notifications about deletes (we still support that
	// for backward compatibility but will be pulled in future releases).

	rm := &mqttRetainedMsg{
		Origin: asm.jsa.id,
		Msg:    pp.msg, // will copy these bytes later as we process rm.
		Flags:  pp.flags,
		Source: c.opts.Username,
		Props:  pp.props, // v5 properties to replay to subscribers
	}

	// MQTT 5.0 Message Expiry Interval on a retained message: record the absolute
	// deadline so the remaining interval can be recomputed on replay and the
	// stored message dropped once it expires. A present interval of 0 means the
	// message expires immediately, so the deadline is "now" (distinct from an
	// absent interval, which never expires and leaves the deadline zero). Spec5
	// [3.3.2.3.3].
	if me, ok := mqttMessageExpiry(pp.props); ok {
		rm.expires = time.Now().Add(time.Duration(me) * time.Second)
	}

	if retainSparkbBirth {
		// [tck-id-conformance-mqtt-aware-store] A Sparkplug Aware MQTT Server
		// MUST store NBIRTH and DBIRTH messages as they pass through the MQTT
		// Server.
		//
		// [tck-id-conformance-mqtt-aware-nbirth-mqtt-topic]. A Sparkplug Aware
		// MQTT Server MUST make NBIRTH messages available on a topic of the
		// form: $sparkplug/certificates/namespace/group_id/NBIRTH/edge_node_id
		//
		// [tck-id-conformance-mqtt-aware-dbirth-mqtt-topic] A Sparkplug Aware
		// MQTT Server MUST make DBIRTH messages available on a topic of the
		// form:
		// $sparkplug/certificates/namespace/group_id/DBIRTH/edge_node_id/device_id
		topic := append(sparkbCertificatesTopicPrefix, pp.topic...)
		subject, _ := mqttTopicToNATSPubSubject(topic)
		rm.Topic = string(topic)
		rm.Subject = string(subject)

		// will use to save the retained message.
		key = string(subject)

		// Store the retained message with the RETAIN flag set.
		rm.Flags |= mqttPubFlagRetain

		if pp.sz > 0 {
			// Copy the payload out of pp since we will be sending the message
			// asynchronously.
			msg := make([]byte, pp.sz)
			copy(msg, pp.msg[:pp.sz])
			asm.jsa.sendMsg(key, msg)
		}

	} else { // isRetained
		// Spec [MQTT-3.3.1-5]. Store the retained message with its QoS.
		//
		// When coming from a publish protocol, `pp` is referencing a stack
		// variable that itself possibly references the read buffer.
		rm.Topic = string(pp.topic)
	}

	// Set the key to the subject of the message for retained, or the composed
	// $sparkplug subject for sparkB.
	rm.Subject = key
	rmBytes, hdr := mqttEncodeRetainedMessageTTL(rm, !asm.rmsgsStreamNoTTL) // will copy the payload bytes
	_, err := asm.jsa.storeMsg(mqttRetainedMsgsStreamSubject+key, hdr, rmBytes)
	if err != nil {
		c.mu.Lock()
		acc := c.acc
		c.mu.Unlock()
		c.Errorf("unable to store retained message for account %q, subject %q: %v",
			acc.GetName(), key, err)
	}
}

// After a config reload, it is possible that the source of a publish retained
// message is no longer allowed to publish on the given topic. If that is the
// case, the retained message is removed from the map and will no longer be
// sent to (re)starting subscriptions.
//
// Server lock MUST NOT be held on entry.
func (s *Server) mqttCheckPubRetainedPerms() {
	sm := &s.mqtt.sessmgr
	sm.mu.RLock()
	done := len(sm.sessions) == 0
	sm.mu.RUnlock()

	if done {
		return
	}

	s.mu.Lock()
	users := make(map[string]*User, len(s.users))
	for un, u := range s.users {
		users[un] = u
	}
	s.mu.Unlock()

	// First get a list of all of the sessions.
	sm.mu.RLock()
	asms := make([]*mqttAccountSessionManager, 0, len(sm.sessions))
	for _, asm := range sm.sessions {
		asms = append(asms, asm)
	}
	sm.mu.RUnlock()

	// For each session we will obtain a list of retained messages.
	var _rms [128]uint64
	rms := _rms[:0]
	for _, asm := range asms {
		// Get all of the retained messages. Then we will sort them so
		// that they are in sequence order, which should help the file
		// store to not have to load out-of-order blocks so often.
		asm.mu.RLock()
		rms = rms[:0] // reuse slice
		// Copy the sequence out of the tree. The tree entry itself can be
		// updated concurrently by addRetainedMsg() after we release the lock,
		// so keeping a pointer here would race with the later sort.
		asm.retmsgs.IterOrdered(func(_ []byte, rm *mqttRetainedMsgRef) bool {
			rms = append(rms, rm.sseq)
			return true
		})
		jsaID := asm.jsa.id
		asm.mu.RUnlock()
		slices.Sort(rms)

		perms := map[string]*mqttPerm{}
		for _, rf := range rms {
			jsm, err := asm.jsa.loadMsg(mqttRetainedMsgsStreamName, rf)
			if err != nil || jsm == nil {
				continue
			}
			rm, err := mqttDecodeRetainedMessage(jsm.Subject, jsm.Header, jsm.Data)
			if err != nil {
				continue
			}
			// We deal only with messages that have a source (the username that produced
			// this message) and were produced on this server.
			if rm.Source == _EMPTY_ || rm.Origin != jsaID {
				continue
			}
			// Lookup source from global users.
			u := users[rm.Source]
			if u != nil {
				p, ok := perms[rm.Source]
				if !ok {
					p = generatePubPerms(u.Permissions)
					perms[rm.Source] = p // possibly nil
				}
				// If there is permission and no longer allowed to publish in
				// the subject, remove the publish retained message from the map.
				if p != nil && !pubAllowed(p, rm.Subject) {
					u = nil
				}
			}

			// Not present or permissions have changed such that the source can't
			// publish on that subject anymore: delete this retained message.
			if u == nil {
				// Set the payload to empty to notify that we are deleting this
				// retained message. We will send this message async.
				rm.Msg = nil
				rmBytes, hdrLen := mqttEncodeRetainedMessage(rm)
				asm.jsa.storeMsgNoWait(mqttRetainedMsgsStreamSubject+rm.Subject, hdrLen, rmBytes)
			}
		}
	}
}

// Helper to generate only pub permissions from a Permissions object
type mqttPerm struct {
	allow *gsl.SimpleSublist
	deny  *gsl.SimpleSublist
}

func generatePubPerms(perms *Permissions) *mqttPerm {
	// If given permissions is `nil`, then it means that permissions block
	// has been removed (so the user is now allowed to publish on everything)
	// or was never there in the first place. Returning `nil` will let the
	// caller know that there are no permissions to enforce.
	if perms == nil {
		return nil
	}
	var p *mqttPerm
	if perms.Publish.Allow != nil {
		p = &mqttPerm{}
		p.allow = gsl.NewSimpleSublist()
		for _, pubSubject := range perms.Publish.Allow {
			_ = p.allow.Insert(pubSubject, struct{}{})
		}
	}
	if len(perms.Publish.Deny) > 0 {
		if p == nil {
			p = &mqttPerm{}
		}
		p.deny = gsl.NewSimpleSublist()
		for _, pubSubject := range perms.Publish.Deny {
			_ = p.deny.Insert(pubSubject, struct{}{})
		}
	}
	return p
}

// Helper that checks if given `perms` allow to publish on the given `subject`
func pubAllowed(perms *mqttPerm, subject string) bool {
	if perms == nil {
		return true
	}
	allowed := true
	if perms.allow != nil {
		allowed = perms.allow.HasInterest(subject)
	}
	// If we have a deny list and are currently allowed, check that as well.
	if allowed && perms.deny != nil {
		allowed = !perms.deny.HasInterest(subject)
	}
	return allowed
}

func (c *client) mqttEnqueuePubResponse(packetType byte, pi uint16, trace bool) {
	c.mqttEnqueuePubResponseReason(packetType, pi, mqttReasonSuccess, trace)
}

func (c *client) mqttEnqueuePubResponseReason(packetType byte, pi uint16, reason byte, trace bool) {
	proto := [5]byte{packetType, 0x2, 0, 0, 0}
	proto[2] = byte(pi >> 8)
	proto[3] = byte(pi)
	n := 4
	// A non-success reason needs the longer v5 form: PI + reason code,
	// properties omitted. Spec5 [3.4.2.1]. 3.1.1 has no reason codes.
	if reason != mqttReasonSuccess && c.mqtt.proto == mqttProtoLevel5 {
		proto[1] = 0x3
		proto[4] = reason
		n = 5
	}

	// Bits 3,2,1 and 0 of the fixed header in the PUBREL Control Packet are
	// reserved and MUST be set to 0,0,1 and 0 respectively. The Server MUST treat
	// any other value as malformed and close the Network Connection [MQTT-3.6.1-1].
	if packetType == mqttPacketPubRel {
		proto[0] |= 0x2
	}

	c.mu.Lock()
	c.enqueueProto(proto[:n])
	c.mu.Unlock()

	if trace {
		name := "(???)"
		switch packetType {
		case mqttPacketPubAck:
			name = "PUBACK"
		case mqttPacketPubRec:
			name = "PUBREC"
		case mqttPacketPubRel:
			name = "PUBREL"
		case mqttPacketPubComp:
			name = "PUBCOMP"
		}
		if n == 5 {
			c.traceOutOp(name, []byte(fmt.Sprintf("pi=%v rc=%v", pi, reason)))
		} else {
			c.traceOutOp(name, []byte(fmt.Sprintf("pi=%v", pi)))
		}
	}
}

func mqttParsePIPacket(r *mqttReader) (uint16, error) {
	pi, err := r.readUint16("packet identifier")
	if err != nil {
		return 0, err
	}
	if pi == 0 {
		return 0, errMQTTPacketIdentifierIsZero
	}
	return pi, nil
}

// mqttParsePubResponsePacket parses an inbound PUBACK/PUBREC/PUBREL/PUBCOMP. In
// MQTT 5.0 these packets may carry a reason code and a properties block after
// the packet identifier. The reason code is returned so the caller can honor
// failure codes (e.g. a PUBREC >= 0x80 must not be answered with a PUBREL,
// Spec5 [4.3.3]); an absent reason code (short form, or 3.1.1) is Success
// (0x00). It consumes exactly pl bytes so the reader is positioned at the start
// of the next packet. Spec5 [3.4.2.1] and following.
func mqttParsePubResponsePacket(r *mqttReader, proto byte, pl int) (uint16, byte, error) {
	end := r.pos + pl
	pi, err := mqttParsePIPacket(r)
	if err != nil {
		return 0, 0, err
	}
	reason := mqttReasonSuccess
	if proto == mqttProtoLevel5 {
		// Optional reason code (1 byte).
		if r.pos < end {
			if reason, err = r.readByte("reason code"); err != nil {
				return 0, 0, err
			}
		}
		// Optional properties. The allowed property set (Reason String, User
		// Property) is identical across the four pub-response packets, so the
		// PUBACK context is sufficient for validation.
		if r.pos < end {
			if _, err = r.readProperties(mqttPacketPubAck); err != nil {
				return 0, 0, err
			}
		}
	}
	if r.pos != end {
		return 0, 0, fmt.Errorf("invalid remaining length %d for pub-response packet", pl)
	}
	return pi, reason, nil
}

// Process a PUBACK (QoS1) or a PUBREC (QoS2) packet, acting as Sender. Set
// isPubRec to false to process as a PUBACK. reason is the MQTT 5.0 reason code
// (Success for 3.1.1 or the short form). A PUBREC carrying a failure code
// (>= 0x80) means the receiver rejected the QoS2 message: per Spec5 [4.3.3] the
// sender MUST NOT send a PUBREL and treats the message as unacknowledged/done,
// so we release the packet identifier and stop redelivery without moving it
// into the PUBREL (awaiting-PUBCOMP) state.
//
// Runs from the client's readLoop. No lock held on entry.
func (c *client) mqttProcessPublishReceived(pi uint16, isPubRec bool, reason byte) (err error) {
	sess := c.mqtt.sess
	if sess == nil {
		return errMQTTInvalidSession
	}

	pubRecFailed := isPubRec && reason >= 0x80

	var jsAckSubject string
	sess.mu.Lock()
	// Must be the same client, and the session must have been setup for QoS2.
	if sess.c != c {
		sess.mu.Unlock()
		return errMQTTInvalidSession
	}
	if isPubRec && !pubRecFailed {
		// The JS ACK subject for the PUBREL will be filled in at the delivery
		// attempt.
		sess.trackAsPubRel(pi, _EMPTY_)
	}
	jsAckSubject = sess.untrackPublish(pi)
	sess.mu.Unlock()

	if isPubRec && !pubRecFailed {
		natsMsg, headerLen := mqttNewDeliverablePubRel(pi)
		_, err = sess.jsa.storeMsg(sess.pubRelSubject, headerLen, natsMsg)
		if err != nil {
			// Failure to send out PUBREL will terminate the connection.
			return err
		}
	}

	// Send the ack to JS to remove the pending message from the consumer. On a
	// failed PUBREC this still applies: the receiver has rejected the message,
	// so it must not be redelivered.
	sess.jsa.sendAck(jsAckSubject)
	return nil
}

func (c *client) mqttProcessPubAck(pi uint16) error {
	return c.mqttProcessPublishReceived(pi, false, mqttReasonSuccess)
}

func (c *client) mqttProcessPubRec(pi uint16, reason byte) error {
	return c.mqttProcessPublishReceived(pi, true, reason)
}

// Runs from the client's readLoop. No lock held on entry.
func (c *client) mqttProcessPubComp(pi uint16) {
	sess := c.mqtt.sess
	if sess == nil {
		return
	}

	var jsAckSubject string
	sess.mu.Lock()
	if sess.c != c {
		sess.mu.Unlock()
		return
	}
	jsAckSubject = sess.untrackPubRel(pi)
	sess.mu.Unlock()

	// Send the ack to JS to remove the pending message from the consumer.
	sess.jsa.sendAck(jsAckSubject)
}

// Return the QoS from the given PUBLISH protocol's flags
func mqttGetQoS(flags byte) byte {
	return flags & mqttPubFlagQoS >> 1
}

func mqttIsRetained(flags byte) bool {
	return flags&mqttPubFlagRetain != 0
}

func sparkbParseBirthDeathTopic(topic []byte) (isBirth, isDeath, isCertificate bool) {
	if bytes.HasPrefix(topic, sparkbCertificatesTopicPrefix) {
		isCertificate = true
		topic = topic[len(sparkbCertificatesTopicPrefix):]
	}
	if !bytes.HasPrefix(topic, sparkbNamespaceTopicPrefix) {
		return false, false, false
	}
	topic = topic[len(sparkbNamespaceTopicPrefix):]

	parts := bytes.Split(topic, []byte{'/'})
	if len(parts) < 3 || len(parts) > 4 {
		return false, false, false
	}
	typ := bytesToString(parts[1])
	switch typ {
	case sparkbNBIRTH, sparkbDBIRTH:
		isBirth = true
	case sparkbNDEATH, sparkbDDEATH:
		isDeath = true
	default:
		return false, false, false
	}
	return isBirth, isDeath, isCertificate
}

//////////////////////////////////////////////////////////////////////////////
//
// SUBSCRIBE related functions
//
//////////////////////////////////////////////////////////////////////////////

func (c *client) mqttParseSubs(r *mqttReader, b byte, pl int) (uint16, []*mqttFilter, error) {
	return c.mqttParseSubsOrUnsubs(r, b, pl, true)
}

func (c *client) mqttParseSubsOrUnsubs(r *mqttReader, b byte, pl int, sub bool) (uint16, []*mqttFilter, error) {
	var expectedFlag byte
	var action string
	if sub {
		expectedFlag = mqttSubscribeFlags
	} else {
		expectedFlag = mqttUnsubscribeFlags
		action = "un"
	}
	// Spec [MQTT-3.8.1-1], [MQTT-3.10.1-1]
	if rf := b & 0xf; rf != expectedFlag {
		return 0, nil, fmt.Errorf("wrong %ssubscribe reserved flags: %x", action, rf)
	}
	pi, err := mqttParsePIPacket(r)
	if err != nil {
		return 0, nil, err
	}
	// end is the absolute end of this packet. It is unaffected by the v5
	// properties block below, which only advances r.pos within [r.pos, end).
	end := r.pos + (pl - 2)
	// MQTT 5.0: a properties block follows the packet identifier in both
	// SUBSCRIBE and UNSUBSCRIBE. Spec5 [3.8.2.1], [3.10.2.1].
	if c.mqtt.proto == mqttProtoLevel5 {
		ctx := mqttPacketSub
		if !sub {
			ctx = mqttPacketUnsub
		}
		props, perr := r.readProperties(ctx)
		if perr != nil {
			return 0, nil, perr
		}
		// Subscription identifiers are not implemented (advertised as
		// unavailable in CONNACK), so reject a SUBSCRIBE carrying one rather
		// than silently ignoring it. Spec5 [3.8.4].
		if sub && props != nil && len(props.subIDs) > 0 {
			return 0, nil, fmt.Errorf("MQTT subscription identifiers are not supported")
		}
	}
	var filters []*mqttFilter
	for r.pos < end {
		// Don't make a copy now because, this will happen during conversion
		// or when processing the sub.
		topic, err := r.readBytes("topic filter", false)
		if err != nil {
			return 0, nil, err
		}
		if len(topic) == 0 {
			return 0, nil, errMQTTTopicFilterCannotBeEmpty
		}
		// Spec [MQTT-3.8.3-1], [MQTT-3.10.3-1]
		if err := mqttValidateTopic(topic, "topic filter"); err != nil {
			return 0, nil, err
		}
		var qos, reason byte
		// We are going to report if we had an error during the conversion,
		// but we don't fail the parsing. When processing the sub, we will
		// have an error then, and the processing of subs code will send
		// the proper mqttSubAckFailure flag for this given subscription.
		filter, err := mqttFilterToNATSSubject(topic)
		if err != nil {
			c.Errorf("invalid topic %q: %v", topic, err)
		}
		if sub {
			if c.mqtt.proto == mqttProtoLevel5 {
				// v5 replaces the single QoS byte with a Subscription Options
				// byte. Spec5 [3.8.3.1].
				var opts byte
				opts, err = r.readByte("subscription options")
				if err != nil {
					return 0, nil, err
				}
				// Only the QoS bits (0-1) are honored by this foundation. No
				// Local (bit 2), Retain As Published (bit 3), Retain Handling
				// (bits 4-5) and the reserved bits (6-7) are not implemented.
				// Rather than ACK a SUBACK success for options we would then
				// silently ignore (e.g. still replaying retained messages for a
				// client that requested Retain Handling=2), reject the
				// SUBSCRIBE. A compliant client using only defaults (all these
				// bits 0) is unaffected. Spec5 [3.8.3.1].
				if opts&0xFC != 0 {
					return 0, nil, fmt.Errorf("%w: options byte 0x%x sets No Local, Retain As Published, Retain Handling or reserved bits", errMQTTUnsupportedSubOption, opts)
				}
				qos = opts & 0x03
				// Shared Subscriptions are advertised as unavailable in
				// CONNACK, so flag the filter for a 0x9E SUBACK reason code
				// rather than subscribe to "$share/..." as a literal topic.
				// Spec5 [3.9.3], [4.13.2].
				if bytes.HasPrefix(topic, mqttSharedSubPrefix) {
					reason = mqttReasonSharedSubNotSupported
				}
			} else {
				qos, err = r.readByte("QoS")
				if err != nil {
					return 0, nil, err
				}
			}
			// Spec [MQTT-3-8.3-4].
			if qos > 2 {
				return 0, nil, fmt.Errorf("subscribe QoS value must be 0, 1 or 2, got %v", qos)
			}
		}
		f := &mqttFilter{ttopic: topic, filter: string(filter), qos: qos, reason: reason}
		filters = append(filters, f)
	}
	// Spec [MQTT-3.8.3-3], [MQTT-3.10.3-2]
	if len(filters) == 0 {
		return 0, nil, fmt.Errorf("%ssubscribe protocol must contain at least 1 topic filter", action)
	}
	return pi, filters, nil
}

func mqttSubscribeTrace(pi uint16, filters []*mqttFilter) string {
	var sep string
	sb := &strings.Builder{}
	sb.WriteString("[")
	for i, f := range filters {
		sb.WriteString(sep)
		sb.Write(f.ttopic)
		sb.WriteString(" (")
		sb.WriteString(f.filter)
		sb.WriteString(") QoS=")
		sb.WriteString(fmt.Sprintf("%v", f.qos))
		if i == 0 {
			sep = ", "
		}
	}
	sb.WriteString(fmt.Sprintf("] pi=%v", pi))
	return sb.String()
}

// For a MQTT QoS0 subscription, we create a single NATS subscription on the
// actual subject, for instance "foo.bar".
//
// For a MQTT QoS1+ subscription, we create 2 subscriptions, one on "foo.bar"
// (as for QoS0, but sub.mqtt.qos will be 1 or 2), and one on the subject
// "$MQTT.sub.<uid>" which is the delivery subject of the JS durable consumer
// with the filter subject "$MQTT.msgs.foo.bar".
//
// This callback delivers messages to the client as QoS0 messages, either
// because: (a) they have been produced as MQTT QoS0 messages (and therefore
// only this callback can receive them); (b) they are MQTT QoS1+ published
// messages but this callback is for a subscription that is QoS0; or (c) the
// published messages come from (other) NATS publishers on the subject.
//
// This callback must reject a message if it is known to be a QoS1+ published
// message and this is the callback for a QoS1+ subscription because in that
// case, it will be handled by the other callback. This avoid getting duplicate
// deliveries.
func mqttDeliverMsgCbQoS0(sub *subscription, pc *client, _ *Account, subject, reply string, rmsg []byte) {
	if pc.kind == JETSTREAM && len(reply) > 0 && strings.HasPrefix(reply, jsAckPre) {
		return
	}

	// This is the client associated with the subscription.
	cc := sub.client

	// This is immutable
	sess := cc.mqtt.sess

	// Lock here, otherwise we may be called with sub.mqtt == nil. Ignore
	// wildcard subscriptions if this subject starts with '$', per Spec
	// [MQTT-4.7.2-1].
	sess.subsMu.RLock()
	subQoS := sub.mqtt.qos
	ignore := mqttMustIgnoreForReservedSub(sub, subject)
	sess.subsMu.RUnlock()

	if ignore {
		return
	}

	hdr, msg := pc.msgParts(rmsg)
	var topic []byte
	var props []byte
	if pc.isMqtt() {
		// This is an MQTT publisher directly connected to this server.

		// Check the subscription's QoS. If the message was published with a
		// QoS>0 and the sub has the QoS>0 then the message will be delivered by
		// mqttDeliverMsgCbQoS12.
		msgQoS := mqttGetQoS(pc.mqtt.pp.flags)
		if subQoS > 0 && msgQoS > 0 {
			return
		}
		topic = pc.mqtt.pp.topic
		props = pc.mqtt.pp.props
		// If the subject is different than the one in pp.subject, then some
		// mapping/transform occurred and we need to recreate the topic.
		if subject != bytesToString(pc.mqtt.pp.subject) {
			topic = natsSubjectStrToMQTTTopic(subject)
		}

	} else {
		// Non MQTT client, could be NATS publisher, or ROUTER, etc..
		h := mqttParsePublishNATSHeader(hdr)

		// Check the subscription's QoS. If the message was published with a
		// QoS>0 (in the header) and the sub has the QoS>0 then the message will
		// be delivered by mqttDeliverMsgCbQoS12.
		if subQoS > 0 && h != nil && h.qos > 0 {
			return
		}

		// If size is more than what a MQTT client can handle, we should probably reject,
		// for now just truncate.
		if len(msg) > mqttMaxPayloadSize {
			msg = msg[:mqttMaxPayloadSize]
		}
		topic = natsSubjectStrToMQTTTopic(subject)
		if h != nil {
			props = h.props
		}
	}

	// MQTT 5.0 Message Expiry Interval of 0 expires the message immediately, so
	// it must not reach any subscriber, whatever its protocol level. This live
	// path otherwise waits ~0s, so no interval rewrite is needed. Spec5
	// [3.3.2.3.3].
	if len(props) > 0 {
		if _, expired := mqttForwardExpiry(props, 0); expired {
			return
		}
	}

	// Message never has a packet identifier nor is marked as duplicate. A QoS0
	// message dropped for exceeding the client's Maximum Packet Size needs no
	// completion (it is not JetStream-backed here), so the result is ignored.
	pc.mqttEnqueuePublishMsgTo(cc, sub, 0, 0, false, topic, msg, props)
}

// This is the callback attached to a JS durable subscription for a MQTT QoS 1+
// sub. Only JETSTREAM should be sending a message to this subject (the delivery
// subject associated with the JS durable consumer), but in cluster mode, this
// can be coming from a route, gw, etc... We make sure that if this is the case,
// the message contains a NATS/MQTT header that indicates that this is a
// published QoS1+ message.
func mqttDeliverMsgCbQoS12(sub *subscription, pc *client, _ *Account, subject, reply string, rmsg []byte) {
	// Message on foo.bar is stored under $MQTT.msgs.foo.bar, so the subject has to be
	// at least as long as the stream subject prefix "$MQTT.msgs.", and after removing
	// the prefix, has to be at least 1 character long.
	if len(subject) < len(mqttStreamSubjectPrefix)+1 {
		return
	}

	hdr, msg := pc.msgParts(rmsg)
	h := mqttParsePublishNATSHeader(hdr)
	if pc.kind != JETSTREAM && (h == nil || h.qos == 0) {
		// MQTT QoS 0 messages must be ignored, they will be delivered by the
		// other callback, the direct NATS subscription. All JETSTREAM messages
		// will have the header.
		return
	}

	// This is the client associated with the subscription.
	cc := sub.client

	// This is immutable
	sess := cc.mqtt.sess

	// We lock to check some of the subscription's fields and if we need to keep
	// track of pending acks, etc. There is no need to acquire the subsMu RLock
	// since sess.Lock is overarching for modifying subscriptions.
	sess.mu.Lock()
	if sess.c != cc || sub.mqtt == nil {
		sess.mu.Unlock()
		return
	}

	// In this callback we handle only QoS-published messages to QoS
	// subscriptions. Ignore if either is 0, will be delivered by the other
	// callback, mqttDeliverMsgCbQos1.
	var qos byte
	if h != nil {
		qos = h.qos
	}
	if qos > sub.mqtt.qos {
		qos = sub.mqtt.qos
	}
	if qos == 0 {
		sess.mu.Unlock()
		return
	}

	// Check for reserved subject violation. If so, we will send the ack to
	// remove the message, and do nothing else.
	strippedSubj := subject[len(mqttStreamSubjectPrefix):]
	if mqttMustIgnoreForReservedSub(sub, strippedSubj) {
		sess.mu.Unlock()
		sess.jsa.sendAck(reply)
		return
	}

	// A broad wildcard subscription can overlap a subscribe deny clause.
	cc.mu.Lock()
	denied := cc.mperms != nil && cc.checkDenySub(strippedSubj)
	cc.mu.Unlock()
	if denied {
		sess.mu.Unlock()
		sess.jsa.sendAck(reply)
		return
	}

	pi, dup, started := sess.trackPublish(sub.mqtt.jsDur, reply)
	sess.mu.Unlock()

	if pi == 0 {
		// We have reached max pending, don't send the message now.
		// JS will cause a redelivery and if by then the number of pending
		// messages has fallen below threshold, the message will be resent.
		return
	}

	originalTopic := natsSubjectStrToMQTTTopic(strippedSubj)
	var props []byte
	if h != nil {
		props = h.props
	}
	// MQTT 5.0 Message Expiry Interval: a v5 subscriber must receive the interval
	// reduced by the time the message waited in the server; if it has already
	// elapsed the message must not be delivered and its stored copy dropped. The
	// store timestamp is carried in the JetStream ack reply subject. Expiry is a
	// property of the message, so it equally gates delivery to a 3.1.1
	// subscriber (whose properties are then stripped on the wire).
	// Only a message whose onward delivery has NOT started may be dropped on
	// expiry; a redelivery of an already-sent PUBLISH must be resent, not dropped.
	// Spec5 [3.3.2.3.3], [MQTT-4.4.0-1].
	if len(props) > 0 && !started {
		_, _, _, ts, _ := ackReplyInfo(reply)
		var expired bool
		if props, expired = mqttForwardExpiry(props, ts); expired {
			sess.mu.Lock()
			sess.untrackPublish(pi)
			sess.mu.Unlock()
			sess.jsa.sendAck(reply)
			return
		}
	}
	if !pc.mqttEnqueuePublishMsgTo(cc, sub, pi, qos, dup, originalTopic, msg, props) {
		// The PUBLISH exceeds the client's MQTT 5.0 Maximum Packet Size. Discard
		// it and complete the delivery so JetStream does not redeliver it forever:
		// release the packet identifier and ack the JS message. Spec5 [3.1.2.11.4].
		sess.mu.Lock()
		sess.untrackPublish(pi)
		sess.mu.Unlock()
		sess.jsa.sendAck(reply)
	}
}

func mqttDeliverPubRelCb(sub *subscription, pc *client, _ *Account, subject, reply string, rmsg []byte) {
	if sub.client.mqtt == nil || sub.client.mqtt.sess == nil || reply == _EMPTY_ {
		return
	}

	hdr, _ := pc.msgParts(rmsg)
	pi := mqttParsePubRelNATSHeader(hdr)
	if pi == 0 {
		return
	}

	// This is the client associated with the subscription.
	cc := sub.client

	// This is immutable
	sess := cc.mqtt.sess

	sess.mu.Lock()
	if sess.c != cc || sess.pubRelConsumer == nil {
		sess.mu.Unlock()
		return
	}
	sess.trackAsPubRel(pi, reply)
	trace := cc.trace
	sess.mu.Unlock()

	cc.mqttEnqueuePubResponse(mqttPacketPubRel, pi, trace)
}

// The MQTT Server MUST NOT match Topic Filters starting with a wildcard
// character (# or +) with Topic Names beginning with a $ character, Spec
// [MQTT-4.7.2-1]. We will return true if there is a violation.
//
// Session or subMu lock must be held on entry to protect access to sub.mqtt.
func mqttMustIgnoreForReservedSub(sub *subscription, subject string) bool {
	// If the subject does not start with $ nothing to do here.
	if !sub.mqtt.reserved || len(subject) == 0 || subject[0] != mqttReservedPre {
		return false
	}
	return true
}

// Check if a sub is a reserved wildcard. E.g. '#', '*', or '*/" prefix.
func isMQTTReservedSubscription(subject string) bool {
	if len(subject) == 1 && (subject[0] == fwc || subject[0] == pwc) {
		return true
	}
	// Match "*.<>"
	if len(subject) > 1 && (subject[0] == pwc && subject[1] == btsep) {
		return true
	}
	return false
}

func sparkbReplaceDeathTimestamp(msg []byte) []byte {
	const VARINT = 0
	const TIMESTAMP = 1

	orig := msg
	buf := bytes.NewBuffer(make([]byte, 0, len(msg)+16)) // 16 bytes should be enough if we need to add a timestamp
	writeDeathTimestamp := func() {
		// [tck-id-conformance-mqtt-aware-ndeath-timestamp] A Sparkplug Aware
		// MQTT Server MAY replace the timestamp of NDEATH messages. If it does,
		// it MUST set the timestamp to the UTC time at which it attempts to
		// deliver the NDEATH to subscribed clients
		//
		// sparkB spec: 6.4.1. Google Protocol Buffer Schema
		//      optional uint64 timestamp = 1; // Timestamp at message sending time
		//
		// SparkplugB timestamps are milliseconds since epoch, represented as
		// uint64 in go, transmitted as protobuf varint.
		ts := uint64(time.Now().UnixMilli())
		buf.Write(protoEncodeVarint(TIMESTAMP<<3 | VARINT))
		buf.Write(protoEncodeVarint(ts))
	}

	for len(msg) > 0 {
		fieldNumericID, fieldType, size, err := protoScanField(msg)
		if err != nil {
			return orig
		}
		if fieldType != VARINT || fieldNumericID != TIMESTAMP {
			// Add the field as is
			buf.Write(msg[:size])
			msg = msg[size:]
			continue
		}

		writeDeathTimestamp()

		// Add the rest of the message as is, we are done
		buf.Write(msg[size:])
		return buf.Bytes()
	}

	// Add timestamp if we did not find one.
	writeDeathTimestamp()

	return buf.Bytes()
}

// Common function to mqtt delivery callbacks to serialize and send the message
// to the `cc` client.
// mqttEnqueuePublishMsgTo frames and queues an outbound PUBLISH to cc. It
// returns false without sending when the packet would exceed the client's MQTT
// 5.0 Maximum Packet Size; the caller is then responsible for completing the
// message (for QoS1/2, acking the JS delivery so it is not redelivered).
func (c *client) mqttEnqueuePublishMsgTo(cc *client, sub *subscription, pi uint16, qos byte, dup bool, topic, msg, props []byte) bool {
	// [tck-id-conformance-mqtt-aware-nbirth-mqtt-retain] A Sparkplug Aware
	// MQTT Server MUST make NBIRTH messages available on the topic:
	// $sparkplug/certificates/namespace/group_id/NBIRTH/edge_node_id with
	// the MQTT retain flag set to true
	//
	// [tck-id-conformance-mqtt-aware-dbirth-mqtt-retain] A Sparkplug Aware
	// MQTT Server MUST make DBIRTH messages available on the topic:
	// $sparkplug/certificates/namespace/group_id/DBIRTH/edge_node_id/device_id
	// with the MQTT retain flag set to true
	//
	// $sparkplug/certificates messages are sent as NATS messages, so we
	// need to add the retain flag when sending them to MQTT clients.

	retain := false
	isBirth, isDeath, isCertificate := sparkbParseBirthDeathTopic(topic)
	if isBirth && qos == 0 {
		retain = isCertificate
	} else if isDeath && !isCertificate {
		msg = sparkbReplaceDeathTimestamp(msg)
	}

	flags, headerBytes := mqttMakePublishHeader(pi, qos, dup, retain, cc.mqtt.proto == mqttProtoLevel5, topic, props, len(msg))

	// MQTT 5.0 Maximum Packet Size: never send a PUBLISH larger than the client
	// is willing to accept. Discard it instead and let the caller complete the
	// delivery. Spec5 [3.1.2.11.4]. mqtt.maxPacketSize is 0 for 3.1.1 or when the
	// client did not advertise a limit.
	if mp := cc.mqtt.maxPacketSize; mp != 0 && len(headerBytes)+len(msg) > int(mp) {
		return false
	}

	cc.mu.Lock()
	if sub.mqtt.prm != nil {
		for _, data := range sub.mqtt.prm {
			cc.queueOutbound(data)
		}
		sub.mqtt.prm = nil
	}
	cc.queueOutbound(headerBytes)
	cc.queueOutbound(msg)
	c.addToPCD(cc)
	trace := cc.trace
	cc.mu.Unlock()

	if trace {
		pp := mqttPublish{
			topic: topic,
			flags: flags,
			pi:    pi,
			sz:    len(msg),
		}
		cc.traceOutOp("PUBLISH", []byte(mqttPubTrace(&pp)))
	}
	return true
}

// Serializes to the given writer the message for the given subject.
func (w *mqttWriter) WritePublishHeader(pi uint16, qos byte, dup, retained, v5 bool, topic, props []byte, msgLen int) byte {
	// Compute len (will have to add packet id if message is sent as QoS>=1)
	pkLen := 2 + len(topic) + msgLen
	var flags byte

	// Set flags for dup/retained/qos1
	if dup {
		flags |= mqttPubFlagDup
	}
	if retained {
		flags |= mqttPubFlagRetain
	}
	if qos > 0 {
		pkLen += 2
		flags |= qos << 1
	}
	// MQTT 5.0 PUBLISH carries a properties section after the packet identifier.
	// props (when set) is the raw block from the publisher, including its length
	// prefix, forwarded verbatim; otherwise a single 0 length byte. For 3.1.1
	// receivers (v5 false) there is no properties section, which is how
	// properties get stripped when delivering to a 3.1.1 subscriber. Spec5 [3.3.2.3].
	if v5 {
		if len(props) > 0 {
			pkLen += len(props)
		} else {
			pkLen++
		}
	}

	w.WriteByte(mqttPacketPub | flags)
	w.WriteVarInt(pkLen)
	w.WriteBytes(topic)
	if qos > 0 {
		w.WriteUint16(pi)
	}
	if v5 {
		if len(props) > 0 {
			w.Write(props)
		} else {
			w.WriteByte(0)
		}
	}

	return flags
}

// Serializes to the given writer the message for the given subject. For v5
// receivers it appends the properties section (props, if any, else empty).
func mqttMakePublishHeader(pi uint16, qos byte, dup, retained, v5 bool, topic, props []byte, msgLen int) (byte, []byte) {
	headerBuf := newMQTTWriter(mqttInitialPubHeader + len(topic) + len(props))
	flags := headerBuf.WritePublishHeader(pi, qos, dup, retained, v5, topic, props, msgLen)
	return flags, headerBuf.Bytes()
}

// Process the SUBSCRIBE packet.
//
// Process the list of subscriptions and update the given filter
// with the QoS that has been accepted (or failure).
//
// Spec [MQTT-3.8.4-3] says that if an exact same subscription is
// found, it needs to be replaced with the new one (possibly updating
// the qos) and that the flow of publications must not be interrupted,
// which I read as the replacement cannot be a "remove then add" if there
// is a chance that in between the 2 actions, published messages
// would be "lost" because there would not be any matching subscription.
//
// Run from client's readLoop.
// No lock held on entry.
func (c *client) mqttProcessSubs(filters []*mqttFilter) ([]*subscription, error) {
	// Those things are immutable, but since processing subs is not
	// really in the fast path, let's get them under the client lock.
	c.mu.Lock()
	asm := c.mqtt.asm
	sess := c.mqtt.sess
	trace := c.trace
	c.mu.Unlock()

	if err := asm.lockSession(sess, c); err != nil {
		return nil, err
	}
	defer asm.unlockSession(sess)
	return asm.processSubs(sess, c, filters, true, trace)
}

// Cleanup that is performed in processSubs if there was an error.
//
// Runs from client's readLoop.
// Lock not held on entry, but session is in the locked map.
func (sess *mqttSession) cleanupFailedSub(c *client, sub *subscription, cc *ConsumerConfig, jssub *subscription) {
	if sub != nil {
		c.processUnsub(sub.sid)
	}
	if jssub != nil {
		c.processUnsub(jssub.sid)
	}
	if cc != nil {
		sess.deleteConsumer(cc)
	}
}

// Make sure we are set up to deliver PUBREL messages to this QoS2-subscribed
// session.
func (sess *mqttSession) ensurePubRelConsumerSubscription(c *client) error {

	sess.mu.Lock()
	pubRelSubscribed := sess.pubRelSubscribed
	pubRelDeliverySubjectB := sess.pubRelDeliverySubjectB
	pubRelDeliverySubject := sess.pubRelDeliverySubject
	pubRelConsumer := sess.pubRelConsumer
	sess.mu.Unlock()

	// Subscribe before the consumer is created so we don't loose any messages.
	if !pubRelSubscribed {
		_, err := c.processSub(pubRelDeliverySubjectB, nil, pubRelDeliverySubjectB, mqttDeliverPubRelCb, false)
		if err != nil {
			c.Errorf("Unable to create subscription for JetStream consumer on %q: %v", pubRelDeliverySubject, err)
			return err
		}
		sess.mu.Lock()
		sess.pubRelSubscribed = true
		sess.mu.Unlock()
	}

	// If the JS consumer already exists, we are done.
	if pubRelConsumer != nil {
		return nil
	}

	opts := c.srv.getOpts()
	ackWait := opts.MQTT.AckWait
	if ackWait == 0 {
		ackWait = mqttDefaultAckWait
	}
	maxAckPending := int(opts.MQTT.MaxAckPending)
	if maxAckPending == 0 {
		maxAckPending = mqttDefaultMaxAckPending
	}

	sess.mu.Lock()
	pubRelSubject := sess.pubRelSubject
	tmaxack := sess.tmaxack
	idHash := sess.idHash
	id := sess.id
	sess.mu.Unlock()

	// Check that the limit of subs' maxAckPending are not going over the limit
	if after := tmaxack + maxAckPending; after > mqttMaxAckTotalLimit {
		return fmt.Errorf("max_ack_pending for all consumers would be %v which exceeds the limit of %v",
			after, mqttMaxAckTotalLimit)
	}

	ccr := &CreateConsumerRequest{
		Stream: mqttOutStreamName,
		Config: ConsumerConfig{
			DeliverSubject: pubRelDeliverySubject,
			Durable:        mqttPubRelConsumerDurablePrefix + idHash,
			AckPolicy:      AckExplicit,
			DeliverPolicy:  DeliverNew,
			FilterSubject:  pubRelSubject,
			AckWait:        ackWait,
			MaxAckPending:  maxAckPending,
			MemoryStorage:  opts.MQTT.ConsumerMemoryStorage,
		},
	}
	if opts.MQTT.ConsumerInactiveThreshold > 0 {
		ccr.Config.InactiveThreshold = opts.MQTT.ConsumerInactiveThreshold
	}
	if _, err := sess.jsa.createDurableConsumer(ccr); err != nil {
		c.Errorf("Unable to add JetStream consumer for PUBREL for client %q: err=%v", id, err)
		return err
	}
	pubRelConsumer = &ccr.Config
	tmaxack += maxAckPending

	sess.mu.Lock()
	sess.pubRelConsumer = pubRelConsumer
	sess.tmaxack = tmaxack
	sess.mu.Unlock()

	return nil
}

// When invoked with a QoS of 0, looks for an existing JS durable consumer for
// the given sid and if one is found, delete the JS durable consumer and unsub
// the NATS subscription on the delivery subject.
//
// With a QoS > 0, creates or update the existing JS durable consumer along with
// its NATS subscription on a delivery subject.
//
// Session lock is acquired and released as needed. Session is in the locked
// map.
func (sess *mqttSession) processJSConsumer(c *client, subject, sid string,
	qos byte, fromSubProto bool) (*ConsumerConfig, *subscription, error) {

	sess.mu.Lock()
	cc, exists := sess.cons[sid]
	tmaxack := sess.tmaxack
	idHash := sess.idHash
	rmax := sess.rmax
	sess.mu.Unlock()

	// Check if we are already a JS consumer for this SID.
	if exists {
		// If current QoS is 0, it means that we need to delete the existing
		// one (that was QoS > 0)
		if qos == 0 {
			// The JS durable consumer's delivery subject is on a NUID of
			// the form: mqttSubPrefix + <nuid>. It is also used as the sid
			// for the NATS subscription, so use that for the lookup.
			c.mu.Lock()
			sub := c.subs[cc.DeliverSubject]
			c.mu.Unlock()

			sess.mu.Lock()
			delete(sess.cons, sid)
			sess.mu.Unlock()

			sess.deleteConsumer(cc)
			if sub != nil {
				c.processUnsub(sub.sid)
			}
			return nil, nil, nil
		}
		// If this is called when processing SUBSCRIBE protocol, then if
		// the JS consumer already exists, we are done (it was created
		// during the processing of CONNECT).
		if fromSubProto {
			return nil, nil, nil
		}
	}
	// Here it means we don't have a JS consumer and if we are QoS 0,
	// we have nothing to do.
	if qos == 0 {
		return nil, nil, nil
	}
	var err error
	var inbox string
	if exists {
		inbox = cc.DeliverSubject
	} else {
		inbox = mqttSubPrefix + nuid.Next()
		opts := c.srv.getOpts()
		ackWait := opts.MQTT.AckWait
		if ackWait == 0 {
			ackWait = mqttDefaultAckWait
		}
		maxAckPending := int(opts.MQTT.MaxAckPending)
		if maxAckPending == 0 {
			maxAckPending = mqttDefaultMaxAckPending
		}
		// Pace JetStream delivery to the client's Receive Maximum so the
		// in-flight gate rarely drops at the cap (a drop waits out AckWait and
		// reorders). The gate stays the hard bound across subscriptions; a
		// consumer that outlives this connection keeps this cap until deleted.
		if rmax != 0 && int(rmax) < maxAckPending {
			maxAckPending = int(rmax)
		}

		// Check that the limit of subs' maxAckPending are not going over the limit
		if after := tmaxack + maxAckPending; after > mqttMaxAckTotalLimit {
			return nil, nil, fmt.Errorf("max_ack_pending for all consumers would be %v which exceeds the limit of %v",
				after, mqttMaxAckTotalLimit)
		}

		durName := idHash + "_" + nuid.Next()
		ccr := &CreateConsumerRequest{
			Stream: mqttStreamName,
			Config: ConsumerConfig{
				DeliverSubject: inbox,
				Durable:        durName,
				AckPolicy:      AckExplicit,
				DeliverPolicy:  DeliverNew,
				FilterSubject:  mqttStreamSubjectPrefix + subject,
				AckWait:        ackWait,
				MaxAckPending:  maxAckPending,
				MemoryStorage:  opts.MQTT.ConsumerMemoryStorage,
			},
		}
		if opts.MQTT.ConsumerInactiveThreshold > 0 {
			ccr.Config.InactiveThreshold = opts.MQTT.ConsumerInactiveThreshold
		}
		if _, err := sess.jsa.createDurableConsumer(ccr); err != nil {
			c.Errorf("Unable to add JetStream consumer for subscription on %q: err=%v", subject, err)
			return nil, nil, err
		}
		cc = &ccr.Config
		tmaxack += maxAckPending
	}

	// This is an internal subscription on subject like "$MQTT.sub.<nuid>" that is setup
	// for the JS durable's deliver subject.
	sess.mu.Lock()
	sess.tmaxack = tmaxack
	sub, err := sess.processQOS12Sub(c, []byte(inbox), []byte(inbox),
		isMQTTReservedSubscription(subject), qos, cc.Durable, mqttDeliverMsgCbQoS12)
	sess.mu.Unlock()

	if err != nil {
		sess.deleteConsumer(cc)
		c.Errorf("Unable to create subscription for JetStream consumer on %q: %v", subject, err)
		return nil, nil, err
	}
	return cc, sub, nil
}

// Queues the published retained messages for each subscription and signals
// the writeLoop.
func (c *client) mqttSendRetainedMsgsToNewSubs(subs []*subscription) {
	c.mu.Lock()
	for _, sub := range subs {
		if sub.mqtt != nil && sub.mqtt.prm != nil {
			for _, data := range sub.mqtt.prm {
				c.queueOutbound(data)
			}
			sub.mqtt.prm = nil
		}
	}
	c.flushSignal()
	c.mu.Unlock()
}

func (c *client) mqttEnqueueSubAck(pi uint16, filters []*mqttFilter) {
	w := newMQTTWriter(7 + len(filters))
	w.WriteByte(mqttPacketSubAck)
	// The per-filter byte (f.qos) is a granted QoS (0/1/2) or a failure reason
	// code (0x80, or a more specific v5 code such as 0x9E); these are valid
	// SUBACK reason codes, so the payload byte is identical for both protocol
	// levels. v5 only adds a properties block before the reason codes.
	if c.mqtt.proto == mqttProtoLevel5 {
		var vh mqttWriter
		vh.WriteUint16(pi)
		vh.writeProperties(nil)
		for _, f := range filters {
			vh.WriteByte(f.qos)
		}
		w.WriteVarInt(vh.Len())
		w.Write(vh.Bytes())
	} else {
		// packet length is 2 (for packet identifier) and 1 byte per filter.
		w.WriteVarInt(2 + len(filters))
		w.WriteUint16(pi)
		for _, f := range filters {
			w.WriteByte(f.qos)
		}
	}
	c.mu.Lock()
	c.enqueueProto(w.Bytes())
	c.mu.Unlock()
}

//////////////////////////////////////////////////////////////////////////////
//
// UNSUBSCRIBE related functions
//
//////////////////////////////////////////////////////////////////////////////

func (c *client) mqttParseUnsubs(r *mqttReader, b byte, pl int) (uint16, []*mqttFilter, error) {
	return c.mqttParseSubsOrUnsubs(r, b, pl, false)
}

// Process the UNSUBSCRIBE packet.
//
// Given the list of topics, this is going to unsubscribe the low level NATS subscriptions
// and delete the JS durable consumers when applicable.
//
// Runs from the client's readLoop.
// No lock held on entry.
func (c *client) mqttProcessUnsubs(filters []*mqttFilter) error {
	// Those things are immutable, but since processing unsubs is not
	// really in the fast path, let's get them under the client lock.
	c.mu.Lock()
	asm := c.mqtt.asm
	sess := c.mqtt.sess
	c.mu.Unlock()

	if err := asm.lockSession(sess, c); err != nil {
		return err
	}
	defer asm.unlockSession(sess)

	removeJSCons := func(sid string) {
		cc, ok := sess.cons[sid]
		if ok {
			delete(sess.cons, sid)
			sess.deleteConsumer(cc)
			// Need lock here since these are accessed by callbacks
			sess.mu.Lock()
			if seqPis, ok := sess.cpending[cc.Durable]; ok {
				delete(sess.cpending, cc.Durable)
				for _, pi := range seqPis {
					delete(sess.pendingPublish, pi)
				}
				if len(sess.pendingPublish) == 0 {
					sess.last_pi = 0
				}
			}
			sess.mu.Unlock()
		}
	}
	for _, f := range filters {
		sid := f.filter
		// v5 UNSUBACK reports whether the subscription existed; sess.subs is
		// guarded by the session-manager lock held here. Spec5 [3.11.3].
		if _, ok := sess.subs[sid]; !ok {
			f.reason = mqttReasonNoSubscriptionExisted
		}
		// Remove JS Consumer if one exists for this sid
		removeJSCons(sid)
		if err := c.processUnsub([]byte(sid)); err != nil {
			c.Errorf("error unsubscribing from %q: %v", sid, err)
		}
		if mqttNeedSubForLevelUp(sid) {
			subject := sid[:len(sid)-2]
			sid = subject + mqttMultiLevelSidSuffix
			removeJSCons(sid)
			if err := c.processUnsub([]byte(sid)); err != nil {
				c.Errorf("error unsubscribing from %q: %v", subject, err)
			}
		}
	}
	return sess.update(filters, false)
}

func (c *client) mqttEnqueueUnsubAck(pi uint16, filters []*mqttFilter) {
	if c.mqtt.proto == mqttProtoLevel5 {
		// v5 UNSUBACK adds a properties block and one reason code per filter.
		// Spec5 [3.11].
		w := newMQTTWriter(7 + len(filters))
		w.WriteByte(mqttPacketUnsubAck)
		var vh mqttWriter
		vh.WriteUint16(pi)
		vh.writeProperties(nil)
		for _, f := range filters {
			vh.WriteByte(f.reason)
		}
		w.WriteVarInt(vh.Len())
		w.Write(vh.Bytes())
		c.mu.Lock()
		c.enqueueProto(w.Bytes())
		c.mu.Unlock()
		return
	}
	w := newMQTTWriter(4)
	w.WriteByte(mqttPacketUnsubAck)
	w.WriteVarInt(2)
	w.WriteUint16(pi)
	c.mu.Lock()
	c.enqueueProto(w.Bytes())
	c.mu.Unlock()
}

func mqttUnsubscribeTrace(pi uint16, filters []*mqttFilter) string {
	var sep string
	sb := strings.Builder{}
	sb.WriteString("[")
	for i, f := range filters {
		sb.WriteString(sep)
		sb.Write(f.ttopic)
		sb.WriteString(" (")
		sb.WriteString(f.filter)
		sb.WriteString(")")
		if i == 0 {
			sep = ", "
		}
	}
	sb.WriteString(fmt.Sprintf("] pi=%v", pi))
	return sb.String()
}

//////////////////////////////////////////////////////////////////////////////
//
// PINGREQ/PINGRESP related functions
//
//////////////////////////////////////////////////////////////////////////////

func (c *client) mqttEnqueuePingResp() {
	c.mu.Lock()
	c.enqueueProto(mqttPingResponse)
	c.mu.Unlock()
}

//////////////////////////////////////////////////////////////////////////////
//
// Trace functions
//
//////////////////////////////////////////////////////////////////////////////

func errOrTrace(err error, trace string) []byte {
	if err != nil {
		return []byte(err.Error())
	}
	return []byte(trace)
}

//////////////////////////////////////////////////////////////////////////////
//
// Subject/Topic conversion functions
//
//////////////////////////////////////////////////////////////////////////////

// Converts an MQTT Topic Name to a NATS Subject (used by PUBLISH)
// See mqttToNATSSubjectConversion() for details.
func mqttTopicToNATSPubSubject(mt []byte) ([]byte, error) {
	return mqttToNATSSubjectConversion(mt, false)
}

// Converts an MQTT Topic Filter to a NATS Subject (used by SUBSCRIBE)
// See mqttToNATSSubjectConversion() for details.
func mqttFilterToNATSSubject(filter []byte) ([]byte, error) {
	return mqttToNATSSubjectConversion(filter, true)
}

// Converts an MQTT Topic Name or Filter to a NATS Subject.
// In MQTT:
// - a Topic Name does not have wildcard (PUBLISH uses only topic names).
// - a Topic Filter can include wildcards (SUBSCRIBE uses those).
// - '+' and '#' are wildcard characters (single and multiple levels respectively)
// - '/' is the topic level separator.
//
// Conversion that occurs:
//   - '/' is replaced with '/.' if it is the first character in mt
//   - '/' is replaced with './' if the last or next character in mt is '/'
//     For instance, foo//bar would become foo./.bar
//   - '/' is replaced with '.' for all other conditions (foo/bar -> foo.bar)
//   - '.' is replaced with '//'.
//   - ' ' cause an error to be returned.
//
// If there is no need to convert anything (say "foo" remains "foo"), then
// the no memory is allocated and the returned slice is the original `mt`.
func mqttToNATSSubjectConversion(mt []byte, wcOk bool) ([]byte, error) {
	var cp bool
	var j int
	res := mt

	makeCopy := func(i int) {
		cp = true
		res = make([]byte, 0, len(mt)+10)
		if i > 0 {
			res = append(res, mt[:i]...)
		}
	}

	end := len(mt) - 1
	for i := 0; i < len(mt); i++ {
		switch mt[i] {
		case mqttTopicLevelSep:
			if i == 0 || res[j-1] == btsep {
				if !cp {
					makeCopy(0)
				}
				res = append(res, mqttTopicLevelSep, btsep)
				j++
			} else if i == end || mt[i+1] == mqttTopicLevelSep {
				if !cp {
					makeCopy(i)
				}
				res = append(res, btsep, mqttTopicLevelSep)
				j++
			} else {
				if !cp {
					makeCopy(i)
				}
				res = append(res, btsep)
			}
		case ' ', '\t', '\n', '\r', '\f':
			// We cannot support whitespace in the MQTT topic/filter — these
			// characters would also corrupt the NATS wire protocol when the
			// subject is forwarded to other connection types (e.g. leaf
			// nodes) where the resulting control line could be split.
			return nil, errMQTTUnsupportedCharacters
		case 0x7f:
			// SubjectTree uses DEL as an internal pivot marker, so retained
			// subjects containing it cannot be indexed safely, including
			// legacy retained messages recovered from the retained-message
			// stream.
			return nil, errMQTTUnsupportedCharacters
		case btsep:
			if !cp {
				makeCopy(i)
			}
			res = append(res, mqttTopicLevelSep, mqttTopicLevelSep)
			j++
		case mqttSingleLevelWC, mqttMultiLevelWC:
			if !wcOk {
				// Spec [MQTT-3.3.2-2] and [MQTT-4.7.1-1]
				// The wildcard characters can be used in Topic Filters, but MUST NOT be used within a Topic Name
				return nil, fmt.Errorf("wildcards not allowed in publish's topic: %q", mt)
			}
			if !cp {
				makeCopy(i)
			}
			if mt[i] == mqttSingleLevelWC {
				res = append(res, pwc)
			} else {
				res = append(res, fwc)
			}
		default:
			if cp {
				res = append(res, mt[i])
			}
		}
		j++
	}
	if cp && res[j-1] == btsep {
		res = append(res, mqttTopicLevelSep)
		j++
	}
	return res[:j], nil
}

// Converts a NATS subject to MQTT topic. This is for publish
// messages only, so there is no checking for wildcards.
// Rules are reversed of mqttToNATSSubjectConversion.
func natsSubjectStrToMQTTTopic(subject string) []byte {
	return natsSubjectToMQTTTopic(stringToBytes(subject))
}

func natsSubjectToMQTTTopic(subject []byte) []byte {
	topic := make([]byte, len(subject))
	end := len(subject) - 1
	var j int
	for i := 0; i < len(subject); i++ {
		switch subject[i] {
		case mqttTopicLevelSep:
			if i < end {
				switch c := subject[i+1]; c {
				case btsep, mqttTopicLevelSep:
					if c == btsep {
						topic[j] = mqttTopicLevelSep
					} else {
						topic[j] = btsep
					}
					j++
					i++
				default:
				}
			}
		case btsep:
			topic[j] = mqttTopicLevelSep
			j++
		default:
			topic[j] = subject[i]
			j++
		}
	}
	return topic[:j]
}

// Returns true if the subject has more than 1 token and ends with ".>"
func mqttNeedSubForLevelUp(subject string) bool {
	if len(subject) < 3 {
		return false
	}
	end := len(subject)
	if subject[end-2] == '.' && subject[end-1] == fwc {
		return true
	}
	return false
}

//////////////////////////////////////////////////////////////////////////////
//
// MQTT Reader functions
//
//////////////////////////////////////////////////////////////////////////////

func (r *mqttReader) reset(buf []byte) {
	if l := len(r.pbuf); l > 0 {
		tmp := make([]byte, l+len(buf))
		copy(tmp, r.pbuf)
		copy(tmp[l:], buf)
		buf = tmp
		r.pbuf = nil
	}
	r.buf = buf
	r.pos = 0
	r.pstart = 0
}

func (r *mqttReader) hasMore() bool {
	return r.pos != len(r.buf)
}

func (r *mqttReader) readByte(field string) (byte, error) {
	if r.pos == len(r.buf) {
		return 0, fmt.Errorf("error reading %s: %v", field, io.EOF)
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *mqttReader) readPacketLen(maxLen int32) (int, bool, error) {
	v, complete, err := r.readVarInt()
	if err != nil {
		return 0, false, err
	}
	if complete {
		packetEnd := r.pos + v
		packetLen := packetEnd - r.pstart
		if maxLen != jwt.NoLimit && int64(packetLen) > int64(maxLen) {
			return packetLen, false, ErrMaxPayload
		}
		if packetEnd <= len(r.buf) {
			return v, true, nil
		}
	}
	r.pbuf = make([]byte, len(r.buf)-r.pstart)
	copy(r.pbuf, r.buf[r.pstart:])
	return 0, false, nil
}

func (r *mqttReader) readVarInt() (int, bool, error) {
	m := 1
	v := 0
	for {
		var b byte
		if r.pos != len(r.buf) {
			b = r.buf[r.pos]
			r.pos++
		} else {
			break
		}
		v += int(b&0x7f) * m
		if (b & 0x80) == 0 {
			return v, true, nil
		}
		m *= 0x80
		if m > 0x200000 {
			return 0, false, errMQTTMalformedVarInt
		}
	}
	return 0, false, nil
}

func (r *mqttReader) readString(field string) (string, error) {
	var s string
	bs, err := r.readBytes(field, false)
	if err == nil {
		s = string(bs)
	}
	return s, err
}

func (r *mqttReader) readBytes(field string, cp bool) ([]byte, error) {
	luint, err := r.readUint16(field)
	if err != nil {
		return nil, err
	}
	l := int(luint)
	if l == 0 {
		return nil, nil
	}
	start := r.pos
	if start+l > len(r.buf) {
		return nil, fmt.Errorf("error reading %s: %v", field, io.ErrUnexpectedEOF)
	}
	r.pos += l
	b := r.buf[start:r.pos]
	if cp {
		b = copyBytes(b)
	}
	return b, nil
}

func (r *mqttReader) readUint16(field string) (uint16, error) {
	if len(r.buf)-r.pos < 2 {
		return 0, fmt.Errorf("error reading %s: %v", field, io.ErrUnexpectedEOF)
	}
	start := r.pos
	r.pos += 2
	return binary.BigEndian.Uint16(r.buf[start:r.pos]), nil
}

func (r *mqttReader) readUint32(field string) (uint32, error) {
	if len(r.buf)-r.pos < 4 {
		return 0, fmt.Errorf("error reading %s: %v", field, io.ErrUnexpectedEOF)
	}
	start := r.pos
	r.pos += 4
	return binary.BigEndian.Uint32(r.buf[start:r.pos]), nil
}

//////////////////////////////////////////////////////////////////////////////
//
// MQTT Writer functions
//
//////////////////////////////////////////////////////////////////////////////

func (w *mqttWriter) WriteUint16(i uint16) {
	w.WriteByte(byte(i >> 8))
	w.WriteByte(byte(i))
}

func (w *mqttWriter) WriteUint32(i uint32) {
	w.WriteByte(byte(i >> 24))
	w.WriteByte(byte(i >> 16))
	w.WriteByte(byte(i >> 8))
	w.WriteByte(byte(i))
}

func (w *mqttWriter) WriteString(s string) {
	w.WriteBytes([]byte(s))
}

func (w *mqttWriter) WriteBytes(bs []byte) {
	w.WriteUint16(uint16(len(bs)))
	w.Write(bs)
}

func (w *mqttWriter) WriteVarInt(value int) {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value > 0 {
			b |= 0x80
		}
		w.WriteByte(b)
		if value == 0 {
			break
		}
	}
}

func newMQTTWriter(cap int) *mqttWriter {
	w := &mqttWriter{}
	w.Grow(cap)
	return w
}

//////////////////////////////////////////////////////////////////////////////
//
// MQTT 5.0 properties codec
//
// References to "spec5" here are from
// https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html
//
//////////////////////////////////////////////////////////////////////////////

// mqttPropertyKnown reports whether prop is a property identifier defined by
// MQTT 5.0. Used to give a clearer error for genuinely unknown identifiers.
func mqttPropertyKnown(prop byte) bool {
	switch prop {
	case mqttPropPayloadFormat, mqttPropMessageExpiry, mqttPropContentType,
		mqttPropResponseTopic, mqttPropCorrelationData, mqttPropSubscriptionID,
		mqttPropSessionExpiry, mqttPropAssignedClientID, mqttPropServerKeepAlive,
		mqttPropAuthMethod, mqttPropAuthData, mqttPropRequestProblemInfo,
		mqttPropWillDelay, mqttPropRequestResponseInfo, mqttPropResponseInfo,
		mqttPropServerReference, mqttPropReasonString, mqttPropReceiveMaximum,
		mqttPropTopicAliasMax, mqttPropTopicAlias, mqttPropMaxQoS,
		mqttPropRetainAvailable, mqttPropUserProperty, mqttPropMaxPacketSize,
		mqttPropWildcardSubAvailable, mqttPropSubIDAvailable, mqttPropSharedSubAvailable:
		return true
	}
	return false
}

// mqttPropsContextWill is a pseudo "packet type" used to validate Will
// properties, which travel inside a CONNECT payload but have their own allowed
// property set. It cannot collide with real packet types (multiples of 0x10).
const mqttPropsContextWill = byte(0x01)

// mqttPropertyAllowed reports whether property prop may appear in the given
// context (a packet type, or mqttPropsContextWill for Will properties).
// Spec5 [2.2.2.2] table of which properties belong to which packets.
func mqttPropertyAllowed(prop, ctx byte) bool {
	switch prop {
	case mqttPropPayloadFormat, mqttPropMessageExpiry, mqttPropContentType,
		mqttPropResponseTopic, mqttPropCorrelationData:
		return ctx == mqttPacketPub || ctx == mqttPropsContextWill
	case mqttPropSubscriptionID:
		// A Subscription Identifier is valid only on a SUBSCRIBE and (from the
		// server) on a delivered PUBLISH. A client-to-server PUBLISH MUST NOT
		// carry one (spec5 [MQTT-3.3.4-6]); since we only ever parse inbound
		// (client->server) PUBLISH properties and validate forwarded blocks
		// with the PUBLISH context, disallow it here so both are rejected
		// rather than relayed (subscription identifiers are unsupported and
		// advertised as unavailable).
		return ctx == mqttPacketSub
	case mqttPropSessionExpiry:
		return ctx == mqttPacketConnect || ctx == mqttPacketConnectAck || ctx == mqttPacketDisconnect
	case mqttPropAssignedClientID, mqttPropServerKeepAlive, mqttPropResponseInfo,
		mqttPropMaxQoS, mqttPropRetainAvailable, mqttPropWildcardSubAvailable,
		mqttPropSubIDAvailable, mqttPropSharedSubAvailable:
		return ctx == mqttPacketConnectAck
	case mqttPropAuthMethod, mqttPropAuthData:
		return ctx == mqttPacketConnect || ctx == mqttPacketConnectAck || ctx == mqttPacketAuth
	case mqttPropRequestProblemInfo, mqttPropRequestResponseInfo:
		return ctx == mqttPacketConnect
	case mqttPropWillDelay:
		return ctx == mqttPropsContextWill
	case mqttPropServerReference:
		return ctx == mqttPacketConnectAck || ctx == mqttPacketDisconnect
	case mqttPropReasonString:
		switch ctx {
		case mqttPacketConnectAck, mqttPacketPubAck, mqttPacketPubRec, mqttPacketPubRel,
			mqttPacketPubComp, mqttPacketSubAck, mqttPacketUnsubAck, mqttPacketDisconnect,
			mqttPacketAuth:
			return true
		}
		return false
	case mqttPropReceiveMaximum, mqttPropTopicAliasMax, mqttPropMaxPacketSize:
		return ctx == mqttPacketConnect || ctx == mqttPacketConnectAck
	case mqttPropTopicAlias:
		return ctx == mqttPacketPub
	case mqttPropUserProperty:
		// Allowed in every packet that carries a properties section.
		return true
	}
	return false
}

// readProperties parses an MQTT 5.0 properties block from the reader for the
// given context (packet type or mqttPropsContextWill). The whole packet is
// already buffered by the dispatch loop, so the var-int length must complete.
// It validates length, identifiers, packet-context, and illegal duplicates.
// Returns nil (no error) when the block is present but empty.
// readPropString reads a UTF-8 Encoded String property value and enforces the
// well-formedness rules of Spec5 [MQTT-1.5.4-1]/[MQTT-1.5.4-2] (valid UTF-8, no
// U+0000). Ill-formed values are a Malformed Packet; without this check the
// server would relay protocol-violating bytes on to subscribers.
func (r *mqttReader) readPropString(field string) (string, error) {
	s, err := r.readString(field)
	if err != nil {
		return _EMPTY_, err
	}
	if err = mqttValidateString(s, field); err != nil {
		return _EMPTY_, fmt.Errorf("%w: %v", errMQTTMalformedProperties, err)
	}
	return s, nil
}

func (r *mqttReader) readProperties(ctx byte) (*mqttProperties, error) {
	plen, complete, err := r.readVarInt()
	if err != nil {
		return nil, err
	}
	if !complete {
		return nil, errMQTTMalformedProperties
	}
	if plen == 0 {
		return nil, nil
	}
	end := r.pos + plen
	if end > len(r.buf) {
		return nil, errMQTTMalformedProperties
	}
	props := &mqttProperties{present: make(map[byte]bool)}
	for r.pos < end {
		prop, err := r.readByte("property id")
		if err != nil {
			return nil, err
		}
		if !mqttPropertyAllowed(prop, ctx) {
			if !mqttPropertyKnown(prop) {
				return nil, fmt.Errorf("%w: 0x%x", errMQTTUnknownProperty, prop)
			}
			return nil, fmt.Errorf("%w: 0x%x", errMQTTPropertyNotAllowed, prop)
		}
		// All properties are non-repeatable except User Property and
		// Subscription Identifier. Spec5 [2.2.2.1].
		if prop != mqttPropUserProperty && prop != mqttPropSubscriptionID {
			if props.present[prop] {
				return nil, fmt.Errorf("%w: 0x%x", errMQTTDuplicateProperty, prop)
			}
			props.present[prop] = true
		}
		switch prop {
		case mqttPropPayloadFormat:
			props.payloadFormat, err = r.readByte("payload format indicator")
			if err == nil && props.payloadFormat > 1 {
				// Spec5 [3.3.2.3.2]: only 0 or 1 are defined.
				err = fmt.Errorf("%w: payload format indicator %d", errMQTTProtocolError, props.payloadFormat)
			}
		case mqttPropRequestProblemInfo:
			props.requestProblem, err = r.readByte("request problem information")
			if err == nil && props.requestProblem > 1 {
				// Spec5 [3.1.2.11.7]: a value other than 0 or 1 is a Protocol Error.
				err = fmt.Errorf("%w: request problem information %d", errMQTTProtocolError, props.requestProblem)
			}
		case mqttPropRequestResponseInfo:
			props.requestResponse, err = r.readByte("request response information")
			if err == nil && props.requestResponse > 1 {
				// Spec5 [3.1.2.11.6]: a value other than 0 or 1 is a Protocol Error.
				err = fmt.Errorf("%w: request response information %d", errMQTTProtocolError, props.requestResponse)
			}
		case mqttPropMaxQoS:
			props.maxQoS, err = r.readByte("maximum qos")
		case mqttPropRetainAvailable:
			props.retainAvailable, err = r.readByte("retain available")
		case mqttPropWildcardSubAvailable:
			props.wildcardSubAvail, err = r.readByte("wildcard subscription available")
		case mqttPropSubIDAvailable:
			props.subIDAvail, err = r.readByte("subscription identifier available")
		case mqttPropSharedSubAvailable:
			props.sharedSubAvail, err = r.readByte("shared subscription available")
		case mqttPropServerKeepAlive:
			props.serverKeepAlive, err = r.readUint16("server keep alive")
		case mqttPropReceiveMaximum:
			if props.receiveMax, err = r.readUint16("receive maximum"); err == nil && props.receiveMax == 0 {
				// Spec5 [3.1.2.11.3]: a Receive Maximum value of 0 is a Protocol
				// Error. (Absent means no property, i.e. the default, which we
				// treat as no client-imposed limit.)
				err = fmt.Errorf("%w: receive maximum of 0", errMQTTProtocolError)
			}
		case mqttPropTopicAliasMax:
			props.topicAliasMax, err = r.readUint16("topic alias maximum")
		case mqttPropTopicAlias:
			props.topicAlias, err = r.readUint16("topic alias")
		case mqttPropMessageExpiry:
			props.messageExpiry, err = r.readUint32("message expiry interval")
		case mqttPropSessionExpiry:
			props.sessionExpiry, err = r.readUint32("session expiry interval")
		case mqttPropWillDelay:
			props.willDelay, err = r.readUint32("will delay interval")
		case mqttPropMaxPacketSize:
			// The client is telling us the largest packet it will accept. We
			// honor this on outbound PUBLISH (see mqttEnqueuePublishMsgTo and
			// serializeRetainedMsgsForSub): a PUBLISH exceeding it is discarded
			// rather than sent. Stored on the connection as c.mqtt.maxPacketSize.
			// Spec5 [3.1.2.11.4].
			if props.maxPacketSize, err = r.readUint32("maximum packet size"); err == nil && props.maxPacketSize == 0 {
				// Spec5 [3.1.2.11.4]: a Maximum Packet Size of 0 is a Protocol
				// Error. (Absent means no property, i.e. no client-imposed limit.)
				err = fmt.Errorf("%w: maximum packet size of 0", errMQTTProtocolError)
			}
		case mqttPropContentType:
			props.contentType, err = r.readPropString("content type")
		case mqttPropResponseTopic:
			props.responseTopic, err = r.readPropString("response topic")
			if err == nil && strings.ContainsAny(props.responseTopic, "+#") {
				// Spec5 [3.3.2.3.5]: the Response Topic must not contain
				// wildcard characters; treat it as a Protocol Error.
				err = fmt.Errorf("%w: wildcard in response topic %q", errMQTTProtocolError, props.responseTopic)
			}
		case mqttPropAssignedClientID:
			props.assignedClientID, err = r.readPropString("assigned client identifier")
		case mqttPropAuthMethod:
			props.authMethod, err = r.readPropString("authentication method")
		case mqttPropResponseInfo:
			_, err = r.readPropString("response information")
		case mqttPropServerReference:
			_, err = r.readPropString("server reference")
		case mqttPropReasonString:
			props.reasonString, err = r.readPropString("reason string")
		case mqttPropCorrelationData:
			props.correlationData, err = r.readBytes("correlation data", true)
		case mqttPropAuthData:
			props.authData, err = r.readBytes("authentication data", true)
		case mqttPropSubscriptionID:
			var v int
			var complete bool
			v, complete, err = r.readVarInt()
			if err == nil && !complete {
				err = errMQTTMalformedProperties
			}
			if err == nil {
				// Spec5 [3.3.2.3.8]/[3.8.2.1.2]: a value of 0 is a Protocol Error.
				if v == 0 {
					return nil, fmt.Errorf("%w: subscription identifier of 0", errMQTTProtocolError)
				}
				props.subIDs = append(props.subIDs, v)
			}
		case mqttPropUserProperty:
			var k, val string
			if k, err = r.readPropString("user property key"); err == nil {
				val, err = r.readPropString("user property value")
			}
			if err == nil {
				props.user = append(props.user, mqttUserProperty{key: k, value: val})
			}
		}
		if err != nil {
			return nil, err
		}
	}
	// A property that lied about its length will have advanced past the
	// declared end; reject such packets as malformed. Spec5 [2.2.2.1].
	if r.pos != end {
		return nil, errMQTTMalformedProperties
	}
	return props, nil
}

// encode writes the set properties as a properties body (without the leading
// length). Scalar/byte/int properties are written only when flagged present;
// strings/slices when non-empty. Used by the server to emit properties.
func (p *mqttProperties) encode(w *mqttWriter) {
	if p == nil {
		return
	}
	wb := func(id, v byte) {
		w.WriteByte(id)
		w.WriteByte(v)
	}
	w16 := func(id byte, v uint16) {
		w.WriteByte(id)
		w.WriteUint16(v)
	}
	w32 := func(id byte, v uint32) {
		w.WriteByte(id)
		w.WriteUint32(v)
	}
	if p.present[mqttPropPayloadFormat] {
		wb(mqttPropPayloadFormat, p.payloadFormat)
	}
	if p.present[mqttPropMessageExpiry] {
		w32(mqttPropMessageExpiry, p.messageExpiry)
	}
	if p.present[mqttPropContentType] {
		w.WriteByte(mqttPropContentType)
		w.WriteString(p.contentType)
	}
	if p.present[mqttPropResponseTopic] {
		w.WriteByte(mqttPropResponseTopic)
		w.WriteString(p.responseTopic)
	}
	if p.present[mqttPropCorrelationData] {
		w.WriteByte(mqttPropCorrelationData)
		w.WriteBytes(p.correlationData)
	}
	if p.present[mqttPropSessionExpiry] {
		w32(mqttPropSessionExpiry, p.sessionExpiry)
	}
	if p.present[mqttPropReceiveMaximum] {
		w16(mqttPropReceiveMaximum, p.receiveMax)
	}
	if p.present[mqttPropMaxQoS] {
		wb(mqttPropMaxQoS, p.maxQoS)
	}
	if p.present[mqttPropRetainAvailable] {
		wb(mqttPropRetainAvailable, p.retainAvailable)
	}
	if p.present[mqttPropMaxPacketSize] {
		w32(mqttPropMaxPacketSize, p.maxPacketSize)
	}
	if p.assignedClientID != _EMPTY_ {
		w.WriteByte(mqttPropAssignedClientID)
		w.WriteString(p.assignedClientID)
	}
	if p.present[mqttPropTopicAliasMax] {
		w16(mqttPropTopicAliasMax, p.topicAliasMax)
	}
	if p.present[mqttPropServerKeepAlive] {
		w16(mqttPropServerKeepAlive, p.serverKeepAlive)
	}
	if p.reasonString != _EMPTY_ {
		w.WriteByte(mqttPropReasonString)
		w.WriteString(p.reasonString)
	}
	if p.present[mqttPropWildcardSubAvailable] {
		wb(mqttPropWildcardSubAvailable, p.wildcardSubAvail)
	}
	if p.present[mqttPropSubIDAvailable] {
		wb(mqttPropSubIDAvailable, p.subIDAvail)
	}
	if p.present[mqttPropSharedSubAvailable] {
		wb(mqttPropSharedSubAvailable, p.sharedSubAvail)
	}
	for _, up := range p.user {
		w.WriteByte(mqttPropUserProperty)
		w.WriteString(up.key)
		w.WriteString(up.value)
	}
}

// writeProperties writes a length-prefixed MQTT 5.0 properties block. A nil
// (or empty) set is encoded as a single 0 length byte, which is mandatory in
// every v5 packet that has a properties section. Spec5 [2.2.2.1].
func (w *mqttWriter) writeProperties(p *mqttProperties) {
	if p == nil {
		w.WriteVarInt(0)
		return
	}
	body := newMQTTWriter(0)
	p.encode(body)
	b := body.Bytes()
	w.WriteVarInt(len(b))
	w.Write(b)
}
