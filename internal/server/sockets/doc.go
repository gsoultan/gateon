// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package sockets keeps the gateway's listening sockets open while the
// gateway itself is replaced (ADR 0092).
//
// A restart used to close every listener and bind it again a moment later.
// Between the two, a client was refused. Under systemd the gateway now hands
// each listening socket to the service manager's file-descriptor store as
// soon as it is bound. The manager keeps the socket open across a restart
// and passes it back to the next process, which serves from it instead of
// binding a new one. The socket never closes, so the kernel goes on
// completing handshakes into its accept queue and the new process finds
// those connections waiting.
//
// What this does and does not give:
//
//   - A new connection made during the restart waits and is served; it is
//     not refused.
//   - A request in flight is finished by the old process's drain, as before.
//   - A connection that outlives the drain (a WebSocket, a long TCP stream)
//     is closed, as before. Keeping those would take two processes sharing
//     the accept loop, which is not what this is.
//
// The store is the service manager's. Without one (a container, a binary
// started by hand, Windows) every call here is the plain net call and
// nothing is kept.
//
// A socket is adopted by what it is, read from the socket itself: its type
// and the address it is bound to. The name the manager passes beside it is
// used only to tell the manager which one to drop.
package sockets
