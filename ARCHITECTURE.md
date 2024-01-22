# minivpn design

`minivpn` (after the re-design landed in January 2024) follows a layered design that tries to capture closely the OpenVPN protocol.

* The bottom layer is `networkio`, which deals with network reads and writes (and implements a `networkio.FramingConn`).
* The `packetmuxer` routes both data and control packets under the underlying connection. Multiplexing is needed so that the TLS session sees a [reliable transport](https://community.openvpn.net/openvpn/wiki/SecurityOverview).
* `reliabletransport` implements reordering and acknowledgement for incoming packages, and retransmission for outgoing packets.
* `controlchannel` serializes data according to the control channel format.
* `tlsession` performs a TLS handshake and negotiates a key exchange over the established session. It moves tls records up and down from/towards the `controlchannel`.
* The `datachannel` performs encryption and decryption for IP Tunnel Packets.
* `TUN` is the user-facing interface. It can read and write `[]byte`.
* Finally, the `workersManager` component deals with coordination among all the components.


## Implementation 

* Each layer is implemented as a service, that can be found under its own package in the `internal` path in the source code.
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
             │        │    ctrl │     │       notifyTLS │   shtdwn!│              │
             │        │    2Rel │  rel2Ctrl      │      │          │              │
             │        │       ┌─▼────────────────▼───┐  │          │              │
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