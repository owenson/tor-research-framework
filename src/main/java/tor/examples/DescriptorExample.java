package tor.examples;

import tor.Consensus;
import tor.OnionRouter;

import tor.TorCrypto;
import tor.util.URLUtil;

import java.io.IOException;
import java.util.*;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.codec.binary.Hex;
// We only use this once, so we use the fully-qualified name
//import org.apache.commons.codec.binary.StringUtils;

/**
 * Created by twilsonb on 3/08/2014.
 * Test directory cache responses to multiple descriptor requests
 */
public class DescriptorExample {

    /*
        Test handling of:
            - uncompressed and compressed descriptors,
            - single and multiple descriptors per request

        Tor Directory Specification
        https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt

        Clients MUST handle compressed concatenated information in two forms:
          - A concatenated list of zlib-compressed objects.
          - A zlib-compressed concatenated list of objects.
        Directory servers MAY generate either format: the former requires less
        CPU, but the latter requires less bandwidth.
     */

    // Generally, I'd use "Running,Valid,Stable", because
    // we want routers that have a good chance of being in the consensus and caches,
    // to reduce spurious errors due to genuinely missing descriptors
    // "Running" is essentially a no-op, because non-running routers are not in the consensus
    public static String FLAGS = "Running,Valid,Stable";

    // How many fingerprints do we want to collect?
    // Appendix B, https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt
    //  "Due to squid proxy url limitations at most 96 fingerprints can be retrieved in a single request."

    /*
        The directory specification recommends the following client behaviour:
        No more than 128 descriptors are requested from a single mirror. ...
        After receiving any response client MUST discard any descriptors that it
        did not request.
    */

    // In reality, most caches will handle up to 500,
    // start silently dropping routers at 1000+,
    // (it's unclear in the spec if this is correct or not)
    // and at 1300, tor  will immediately terminate the connection
    //   with "request too large" in its logs

    // Use 10000 or INT_MAX to get all routers with the specified flags
    public static int ROUTER_COUNT = 10;

    // Where we get the router strings we send to the server
    public static Boolean useConsensusRouters = true;
    public static Boolean useRandomHexRouters = false;
    // This option generally makes a mess of everything when turned on,
    // including the Java URL classes and the terminal output
    public static Boolean useRandomByteRouters = false;

    public static int FINGERPRINT_BYTE_LENGTH = 20;
    public static int FINGERPRINT_CHAR_LENGTH = FINGERPRINT_BYTE_LENGTH*2;


    /*
         The Tor directory spec allows fingerprints to be shortened,
         but only when requesting the consensus using *authority* fingerprints:

         http://<hostname>/tor/status-vote/current/consensus/<F1>+<F2>+<F3>.z

        fingerprints can be shortened to a length of any multiple of
        two, using only the leftmost part of the encoded fingerprint.
        Tor uses 3 bytes (6 hex characters) of the fingerprint.
    */

    // The number of characters to use from each fingerprint in requests
    // The tor directory spec says this should be a multiple of 2.
    // We don't enforce this.
    // public static int TRUNCATE_FINGERPRINT_CHAR_LENGTH = 6;

    // It's much better to test against a local instance - it's faster, and reduces the load on the Tor network
    // And you get much better debugging info from both sides
    // And there's much less chance you'll be seen to be launching an (unsolicited) attack
    // However, this also disables retries
    public static String DIRECTORY_SERVER_ADDRESS = "127.0.0.1";
    public static String DIRECTORY_SERVER_PORT = "8880";

    // gho's router - request permission before using
    //public static String DIRECTORY_SERVER_ADDRESS = "37.187.247.150";
    //public static String DIRECTORY_SERVER_PORT = "9030";

    // Fallback to a random directory server if either of these are null
    // TODO: implement default port 9030?
    //public static String DIRECTORY_SERVER_ADDRESS = null;
    //public static String DIRECTORY_SERVER_PORT = null;

    public static void main(String[] args) {
        // Let's only retry twice - we really don't want to get picked up as a DoS attack
        // TODO: we could do this much better with a setter method - on the class or on the object?
        Consensus.MAX_TRIES = 3;

        Consensus con = Consensus.getConsensus();
        TreeMap<String, OnionRouter> orMap = new TreeMap<>();
        TreeSet<String> requestFingerprintList = new TreeSet<>();

        Boolean debugPrintedReply = false;

        // Create a map with ROUTER_COUNT random routers with FLAGS, eliminating duplicates
        // If there are fewer than ROUTER_COUNT routers with FLAGS, use them all
        TreeMap<String, OnionRouter> allWithFlags = con.getORsWithFlag(FLAGS);

        if (allWithFlags.size() <= ROUTER_COUNT) {

            orMap = allWithFlags;

        } else {

            while (orMap.size() < ROUTER_COUNT) {
                OnionRouter router = con.getRandomORWithFlag(FLAGS);

                // Check we're not using the same router multiple times
                // Servers eliminate duplicates, and this messes with our counts
                // Alternately, we could skip the check, and just overwrite the key.
                //   But this logic is clearer.
                if (!orMap.containsKey(router.identityhash))
                    orMap.put(router.identityhash, router);

            }
        }

        /*
            This code is terribly slow for more than around 10 routers, as it launches a request for every one.
            No wonder multiple fingerprints are permitted in a single request!

            This code is obsolete and may not work any more.
        */
        /*
        System.out.println("Retrieve authority descriptors in separate requests");
        System.out.println("===================================================");
        System.out.println("Retrieving single authority descriptors with optimistic compression...");
        for (OnionRouter or: ors.values()) {
            try {
                String descriptor = con.getRouterDescriptor(or.identityhash);
                if (descriptor.startsWith("router ")) {
                    System.out.println("Successfully retrieved descriptor for fingerprint: " + or.identityhash);
                } else {
                    System.err.println("Consistency checks failed on descriptor for fingerprint: " + or.identityhash);
                    System.err.println(descriptor);
                }
            } catch (IOException e) {
                System.err.println("IO Error attempting to retrieve single descriptor for fingerprint: " + or.identityhash
                        + "\n Error: " + e.toString());
            }
        }
        */

        System.out.println("Retrieve authority descriptors in one request");
        System.out.println("=============================================");
        System.out.println("Retrieving multiple authority descriptors with optimistic compression...");

        // Concatenate the identity hashes together, using "+" as a separator
        String fingerprintURLFragment = null;
        for (String identityFingerprint: orMap.keySet()) {

            // Only for requesting consensuses via an (potentially truncated) authority fingerprint
            //String requestFingerprint = StringUtils.left(identityFingerprint, TRUNCATE_FINGERPRINT_CHAR_LENGTH);
            String requestFingerprint = null;

            if (useConsensusRouters) {
                requestFingerprint = identityFingerprint;
            }

            // Flip a coin to decide whether to replace the fingerprint with a random hex string
            if (useRandomHexRouters && (TorCrypto.rnd.nextBoolean() || requestFingerprint == null)) {
                byte[] randomHexBytes = new byte[FINGERPRINT_BYTE_LENGTH];
                TorCrypto.rnd.nextBytes(randomHexBytes);
                // converts to lowercase by default
                requestFingerprint = Hex.encodeHexString(randomHexBytes);

                // Flip a coin to decide whether to uppercase it
                if (TorCrypto.rnd.nextBoolean())
                    requestFingerprint = requestFingerprint.toUpperCase();
            }

            // Flip a coin to decide whether to replace the fingerprint with random binary bytes
            if (useRandomByteRouters && (TorCrypto.rnd.nextBoolean() || requestFingerprint == null)) {
                // Though the name is a little counter-intuitive, in this particular instance
                // we want one byte for every character in the fingerprint
                byte[] randomBinaryBytes = new byte[FINGERPRINT_CHAR_LENGTH];
                TorCrypto.rnd.nextBytes(randomBinaryBytes);

                // Because we need to convert bytes to a Charset, then to a URL,
                // our ability to manipulate what tor sees is limited by the Java APIs.
                // They do an awful lot of sanity checking.

                // This code is as close as we can get to sending random binary data to tor,
                // without writing a basic HTTP client ourselves.

                // And it is hard to replicate requests using binary
                // by copying and pasting from various terminals or logs
                requestFingerprint = org.apache.commons.codec.binary.StringUtils.newStringIso8859_1(randomBinaryBytes);
            }

            if (requestFingerprint != null) {

                // only record real router fingerprints, not garbage
                if (requestFingerprint.equals(identityFingerprint))
                    requestFingerprintList.add(requestFingerprint);

                if (fingerprintURLFragment == null) {
                    fingerprintURLFragment = requestFingerprint;
                } else {
                    fingerprintURLFragment += "+" + requestFingerprint;
                }
            }
        }

        // Now try to retrieve them in a single request
        // Either:
        //  - the InflaterInputStream handles a "concatenated list of zlib-compressed objects" transparently, or
        //  - few servers send a "concatenated list of zlib-compressed objects"
        //    (instead choosing a "zlib-compressed concatenated list of objects")
        String descriptorReply = null;
        try {

            if (DIRECTORY_SERVER_ADDRESS != null && DIRECTORY_SERVER_PORT != null) {
                // Connect to a specified directory (cache)
                // Note: this disables automatic retries
                descriptorReply = con.getRouterDescriptor(fingerprintURLFragment, DIRECTORY_SERVER_ADDRESS, DIRECTORY_SERVER_PORT);
            } else {
                // Connect to a random directory (cache)
                // Note: using multiple, random caches may make errors harder to reproduce
                descriptorReply = con.getRouterDescriptor(fingerprintURLFragment);
            }

            System.out.println("Requested descriptors: " + URLUtil.URLEncode(fingerprintURLFragment));

        } catch (IOException e) {
            System.err.println("IO Error attempting to retrieve descriptor list for "
                    + String.valueOf(orMap.size()) + " fingerprints: "
                    + URLUtil.URLEncode(fingerprintURLFragment)
                    + "\n Error: " + e.toString());
        }

        // Print what we wanted, what we got, and a comparison
        if (descriptorReply != null) {

            int descriptorCount = 0;
            String descriptorLines[] = descriptorReply.split("\n");
            TreeSet<String> replyFingerprints = new TreeSet<>();

            for (String line : descriptorLines) {

                String fp = null;

                // The descriptor fingerprints can have an "opt " in front of them
                if (line.startsWith("fingerprint ")) {
                    fp = line.substring(("fingerprint ").length());
                } else if (line.startsWith("opt fingerprint ")) {
                    fp = line.substring(("opt fingerprint ").length());
                } else if (line.startsWith("router ")) {
                    descriptorCount++;
                }

                if (fp != null) {

                    // Match the consensus fingerprints, which are lowercase and contain no whitespace
                    fp = StringUtils.deleteWhitespace(fp);
                    fp = fp.toLowerCase();

                    if (!replyFingerprints.contains(fp))
                        replyFingerprints.add(fp);
                    else
                        System.err.println("Duplicate fingerprint: " + fp + " in reply.");
                }
            }


            // Do our descriptors appear valid, and did we get the right number of them?
            if (descriptorReply.startsWith("router ") && descriptorCount == orMap.size()) {
                System.out.println("Downloaded " + String.valueOf(descriptorCount)
                        + " descriptors for fingerprints: " + URLUtil.URLEncode(fingerprintURLFragment));
            } else {
                System.err.println();
                System.err.println("Downloaded " + String.valueOf(descriptorCount)
                        + " descriptors for " + String.valueOf(orMap.size())
                        + " fingerprints: " + URLUtil.URLEncode(fingerprintURLFragment));

                //System.err.println();
                // this is often so long that it is larger than the IntelliJ console buffer
                //System.err.println(descriptors);
                //debugPrintedReply = true;
            }

            //TreeSet<String> allFingerprints = new TreeSet<>(requestFingerprintList);
            //allFingerprints.addAll(replyFingerprints);

            if (!requestFingerprintList.equals(replyFingerprints)) {

                if (!debugPrintedReply) {
                    //System.err.println();
                    //System.err.println(descriptors);
                    //debugPrintedReply = true;
                }

                System.err.println();

                // Print what we wanted and what we got
                for (String requestFingerprint : requestFingerprintList)
                    System.err.println("Requested fingerprint: " + requestFingerprint + ".");

                System.err.println();

                for (String replyFingerprint : replyFingerprints)
                    System.err.println("Received fingerprint:  " + replyFingerprint + ".");

                System.err.println();

                // Now list missing and extra fingerprints

                TreeSet<String> missingInReply = new TreeSet<>(requestFingerprintList);
                missingInReply.removeAll(replyFingerprints);

                for (String missingFingerprint : missingInReply)
                    System.err.println("Missing fingerprint:   "
                            + missingFingerprint + ". Requested, but not in reply.");

                TreeSet<String> extraInReply = new TreeSet<>(replyFingerprints);
                extraInReply.removeAll(requestFingerprintList);

                for (String extraFingerprint : extraInReply)
                    System.err.println("Extra fingerprint:     "
                            + extraFingerprint + ". Not requested, but provided in reply.");

                // Try and find missing and extra fingerprint fragments in the descriptors
                // This is error-prone, as fingerprints are space-separated in descriptors
                for (String line : descriptorLines) {
                    for (String fingerprint : missingInReply) {
                        // fingerprints are already lowercase
                        String fragment = StringUtils.left(fingerprint, 4);

                        if (line.toLowerCase().contains(fragment)){
                            System.err.println("Missing fingerprint:   "
                                    + fingerprint + " fragment " + fragment
                                    + " found in descriptor line: " + line);
                        }

                    }

                    for (String fingerprint : extraInReply) {
                        // fingerprints are already lowercase
                        String fragment = StringUtils.left(fingerprint, 4);

                        if (line.toLowerCase().contains(fragment)){
                            System.err.println("Extra fingerprint:     "
                                    + fingerprint + " fragment " + fragment
                                    + " found in descriptor line: " + line);
                        }

                    }
                }

                // Pull up OnionRouter details for missing and extra routers
                for (String fingerprint : missingInReply) {
                    OnionRouter router = con.routers.get(fingerprint);

                    if (router != null){
                        System.err.println("Missing fingerprint:   "
                                + fingerprint + " found router: " + router.toString());
                    }

                }

                for (String fingerprint : extraInReply) {
                    OnionRouter router = con.routers.get(fingerprint);

                    if (router != null){
                        System.err.println("Extra fingerprint:     "
                                + fingerprint + " found router: " + router.toString());
                    }

                }
            }


        }

    }

}
