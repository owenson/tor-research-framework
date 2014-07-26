tor-research-framework
======================
by Gareth Owen (drgowen@gmail.com - www.ghowen.me)

LICENCE: GNU GPL v3

Introduction
============

The framework is a Java Tor client that is designed to be easy to read and modify at the code level.  There are a number of examples in the examples directory on how to use the framework.  Modifying the core framework code should be relatively straight forward for someone loosely familiar with the Tor protocol.

The easiest way to get started is to import the project into IntelliJ and hopefully maven should fetch all the dependencies for you.

Before you do anything, you'll need a copy of the Consensus from a directory authority (which contains a list of nodes in the Tor network).  Code:

    Consensus con = Consensus.getConsensus();
    
After this, you need to pick a guard node.

    OnionRouter guard = con.getRouterByName("southsea0");
    
Now you can connect into the tor network using TorSocket:

    TorSocket sock = new TorSocket(guard);
    
and now, presumably, you'll want to build a circuit:

    TorCircuit circ = sock.createCircuit(true);
    
the true option makes most calls to circ blocking until they have succeeded, you'll know if you want this or not (if you don't use blocking, you can optionally use circ.waitForState().  At this stage, a circuit isn't built, for that you need to do one of two things, either call create() which will establish a circuit to just the first hop, or do the following:

    circ.createRoute("tor26,turtles");
    
which will establish a circuit through the first hop and then extend it to tor26, then turtles.

Once you've got a circuit built, you can create a TorStream:

    TorStream stream = circ.createStream("hostname", port, optionalListenerForEvents);
    
if you choose not to use the listener, you can use stream.waitForState() to wait for it to be in various states before reading.  If its READY then the connection is established, and if its DESTROYED the the connection was closed.

Hidden Service Usage
====================

See the example provided.  Lots of useful functions in HiddenService class.

Advanced Usage
==============

TorSocket creates two threads, one to process incoming cells which it'll automatically handle by passing them off to the respective TorCircuit.handleReceived(), and another to process the send queues of circuits.

To send a packet down a circuit, you can use:

    circ.send(payload, RELAY_*, false, (short)streamID);
    
this will package the payload in a RELAY cell and encrypt it all the way to the last hop and then send it.

To send a raw cell just to the first hop, construct a Cell(circId, cmdId, payload) object and call TorSocket.sendCell().

Troubleshooting
===============

You need the following dependencies installed: apache commons and bouncycastle.

Routers go up and down, if you're just trying the examples, then be aware the hardcoded routers might be offline.


