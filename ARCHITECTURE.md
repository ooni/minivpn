# minivpn design

`minivpn` (after the re-design landed in January 2024) follows a layered design that tries to capture closely the OpenVPN protocol.

* The bottom layer is `networkio`, which deals with network reads and writes (and implements a `networkio.FramingConn`).
* The `packetmuxer` ...


```
         ┌───────────────────────────────────────────┐ startShtdwn ┌──────────────┐
         │                                           ├────────────►│              │
         │    TUN                                    │             │ workers      │
         │                                           │     shtdwn! │ Manager      │
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
           muxer2     │     Down│   tlsRecUp  notifyTLS │          │              │
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