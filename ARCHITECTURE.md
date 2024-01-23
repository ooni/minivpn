# minivpn design

`minivpn` (after the re-design landed in January 2024) follows a layered design that tries to capture closely the OpenVPN protocol.

* The bottom layer is [networkio](https://github.com/ooni/minivpn/tree/main/internal/networkio), which deals with network reads and writes. The module implements a [FramingConn](https://github.com/ainghazal/minivpn/blob/main/internal/networkio/framing.go#L10).
* The [packetmuxer](https://github.com/ainghazal/minivpn/blob/main/internal/packetmuxer/service.go) routes both data and control packets under the underlying connection. Multiplexing is needed so that the TLS session sees a [reliable transport](https://community.openvpn.net/openvpn/wiki/SecurityOverview).
* [reliabletransport](https://github.com/ainghazal/minivpn/blob/main/internal/reliabletransport/reliabletransport.go) implements reordering and acknowledgement for incoming packages, and retransmission for outgoing packets.
* [controlchannel](https://github.com/ainghazal/minivpn/blob/main/internal/controlchannel/controlchannel.go) serializes and deserializes data according to the control channel format; and it reacts to `SOFT_RESET_V1` packets.
* [tlsession](https://github.com/ainghazal/minivpn/blob/main/internal/tlssession/tlssession.go) performs a TLS handshake and negotiates a key exchange over the established session. It moves tls records up and down from/towards the `controlchannel`.
* The [datachannel](https://github.com/ainghazal/minivpn/tree/main/internal/datachannel) performs encryption and decryption for IP Tunnel Packets.
* [TUN](https://github.com/ainghazal/minivpn/blob/main/internal/tun/tun.go) is the user-facing interface. It can read and write `[]byte`.
* Finally, the [workers.Manager](https://github.com/ainghazal/minivpn/blob/main/internal/workers/workers.go) component deals with coordination among all the components.


## Services

* Each layer is implemented as a service, that can be found under its own package under the [internal](https://github.com/ainghazal/minivpn/blob/main/internal) path.
* Each service initializes and starts a number of workers (typicall two: one for moving data up the stack, and another one for moving data down). Some services implement only one worker, some do three.
* The communication among the different components happens via channels.
* Some channels are used for event notification, some channels move sequences of `[]byte` or `*model.Packet`.
* The channels leaving and arriving each module can be seen in the diagram below:


```
                                                        startShtdwn
         ┌───────────────────────────────────────────┬────────────►┌──────────────┐
         │                                           │     shtdwn! │              │
         │    TUN                                    │◄────────────┤ workers      │
         │                                           │     Ready   │ Manager      │
         └────▲───────┬──────────────────────────────┘◄────────────┤              │
              │       │                                            │              │
              │tunUp  │tunDown                                     │              │
         ┌────┴───────▼──────────────────────────────┐             │              │
         │                                           │     shtdwn! │              │
         │   datachannel                             │◄────────────┤              │
         │                                           │             │              │
         └───▲────────┬────────────────────────▲─────┘             │              │
             │        │                  keyUp │           shtdwn! │              │
             │        │       ┌────────────────┴─────┐◄────────────┤              │
             │        │       │                      │             │              │
             │        │       │ tlssession           ◄──┐          │              │
             │        │       └───────▲──────────▲───┘  │          │              │
             │        │     tlsRec    │          │     notifyTLS   │              │
           muxerTo    │     Down│   tlsRecUp  notifyTLS │          │              │
           Data       │         │     │          │      │          │              │
             │        │       ┌─▼─────┴──────────┴───┐  │          │              │
             │        │       │                      │  │          │              │
             │        │       │ controlchannel       │  │          │              │
             │        │       └─┬─────▲──────────────┘  │ ◄────────┤              │
             │        │    ctrl │     │                 │   shtdwn!│              │
             │        │    2Rel │  rel2Ctrl             │          │              │
             │        │       ┌─▼────────────────────┐  │          │              │
             │        │       │                      │  │ ◄────────┤              │
             │        │       │ reliabletransport    │  │   shtdwn!│              │
             │        │       └───────▲──────────────┘  │          │              │
             │     dataOrCtrlToMuxer  │ muxerToReliable │          │              │
             │        │         │     │                 │          │              │
         ┌───┴────────▼─────────▼─────┴──────────────┐  │          │              │
hardReset│                                           │  │          │              │
     ────►   packetkmuxer & HRESET                   ├──┘          │              │
         │                                           │             │              │
         └───────────────────┬────────▲──────────────┘◄────────────┤              │
               muxerToNetwork│        │networkToMuxer      shtdwn! │              │
         ┌───────────────────▼────────┴──────────────┐             │              │
         │                                           │             │              │
         │   network I/O                             │◄────────────┤              │
         │                                           │     shtdwn! │              │
         └───────────────────────────────────────────┘             └──────────────┘
```

# Implementation and liveness analysis

In the layered architecture detailed above, there are 12 different goroutines
tasked with moving data across the stack, in 6 services:

1. **networkio**: 2 workers (up/down).
2. **packetmuxer**: 2 workers (up/down).
3. **reliabletransport**: 2 workers (up/down).
4. **controlchannel**: 2 workers (up/down).
5. **tlssession**: 1 worker
6. **datachannel**: 3 workers (up/down/key).

The `TUN` abstraction reads and writes to the `tunUp` and `tunDown` channels; TUN user is responsible for dialing the connection and passing a `networkio.FramingConn` to the `tun.StartTUN()` constructor. The TUN constructor will own the conn, and will also start an internal session.Manager and workers.Manager to deal with service coordination.

The channel communication between services is designed to be blocking, with unbuffered channels.

```mermaid
stateDiagram-v2
    classDef tunrw font-style:italic,font-weight:bold,fill:yellow


    state "TUN.Write()" as tundown
    state "TUN.Read()" as tunup

    state "datachannel.MoveDownWorker" as datadown
    state "datachannel.MoveUpWorker" as dataup
    state "datachannel.KeyWorker" as datakey

    state "muxer.MoveDownWorker" as muxerdown
    state "muxer.MoveUpWorker" as muxerup

    state "reliable.MoveDownWorker" as reliabledown
    state "reliable.MoveUpWorker" as reliableup

    state "networkio.MoveDownWorker" as networkdown
    state "networkio.MoveUpWorker" as networkup
 
    state "controlchannel.MoveDownWorker" as controldown
    state "controlchannel.MoveUpWorker" as controlup
    state "tlssession.Worker" as tls

    state dataOrCtrlToMuxer <<join>>
    state tlsRecordUp <<join>>
    state tlsRecordDown <<join>>
    state newkey <<join>>

    state notifytls <<join>>

    state internetout <<join>>
    state internetin <<join>>

    [*] --> tundown : []byte
    tundown:::tunrw --> datadown



    datadown --> dataOrCtrlToMuxer
    reliabledown --> dataOrCtrlToMuxer

    dataOrCtrlToMuxer --> muxerdown: <- dataOrCtrlToMuxer
    muxerdown --> networkdown

    controldown --> reliabledown 

    networkdown --> internetout: conn.Write()
    internetin --> networkup: conn.Read()

    tls --> tlsRecordDown: tlsDown <-
    tlsRecordDown --> controldown: <-tlsDown
    tls --> newkey: key<-
    newkey --> datakey: <-key


    state if_data <<choice>>

    muxerup --> if_data 

    muxerup --> notifytls: notifyTLS<-
    controlup --> notifytls: notifyTLS<-
    notifytls --> tls: <-notifyTLS

    
    if_data --> reliableup: isControl?
    if_data --> dataup: isData?

    
    reliableup --> controlup
    reliableup --> reliabledown: ack

    controlup --> tlsRecordUp: tlsUp <-
    tlsRecordUp --> tls: <- tlsUp

    networkup --> muxerup
    dataup --> tunup
    tunup:::tunrw --> [*]
```

## minivpn layered architecture (may 2023)

TODO: converge graph.

```mermaid
stateDiagram
    state "networkio.moveUpWorker {1}" as nioUp
    state "packetmuxer.moveUpWorker {1}" as pmUp
    state "datachannel.moveUpWorker {1}" as dcUp
    state "reliable.moveUpWorker {1}" as relUp
    state "controlchannel.moveUpWorker {1}" as ccUp
    state "tlsstate.Worker {1}" as tlsWorker
    state "TUN.Read() {1}" as tunRead

    nioUp --> pmUp: chan []byte
    pmUp --> dcUp: chan *model.Packet
    pmUp --> relUp: chan *model.Packet
    relUp --> ccUp: chan *model.Packet
    dcUp --> tunRead: chan *TUNPacket [NB, buffered]
    pmUp --> tlsWorker: chan *Notification [NB, !!!]
    ccUp --> tlsWorker: chan *Notification [NB, !!!]
    ccUp --> tlsWorker: chan *TLSRecord
    tunRead --> [*]

    state "networkio.moveDownWorker {1}" as nioDown
    state "datachannel.moveDownWorker {1}" as dcDown
    state "packetmuxer.moveDownWorker {1}" as pmDown
    state "controlchannel.moveDownWorker {1}" as ccDown
    state "TUN.Write() {1}" as tunWrite
    state "reliable.moveDownWorker {1}" as relDown

    tunWrite --> dcDown: chan *TUNPacket
    dcDown --> pmDown: chan *model.Packet
    pmDown --> nioDown: chan []byte [NB, buffered]
    ccDown --> relDown: chan *model.Packet
    relDown --> pmDown: chan *model.Packet
    tlsWorker --> ccDown: chan *TLSRecord
    relUp --> pmDown: chan *model.Packet [ACK]
    [*] --> tunWrite
    tlsWorker --> dcUp: chan *DataChannelKey

    nioDown --> internet: conn.Write() [!!!]
    internet --> nioUp: conn.Read() [!!!]
```
