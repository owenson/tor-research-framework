package tor.examples;

import tor.Consensus;
import tor.OnionRouter;

/**
 * Created by gho on 30/07/14.
 */
public class ConsensusExample {
    public static void main(String[] args) {
        Consensus con = Consensus.getConsensus();

        System.out.println("Listing all bad exits");
        System.out.println("=====================");
        for(OnionRouter or : con.getORsWithFlag(new String[] {"BadExit"}, false).values()) {
            System.out.println(or);
        }

        System.out.println();
        System.out.println("A random Guard node");
        System.out.println("===================");
        OnionRouter or = con.getRandomORWithFlag("Guard,Fast,Valid");
        System.out.println(or);

        System.out.println();
        System.out.println("A random Exit that exits on port 25 (SMTP)");
        System.out.println("===========================================");
        OnionRouter or2 = con.getRandomORWithFlag(new String[] { "Exit" }, 25, false);
        System.out.println(or2);
    }
}
