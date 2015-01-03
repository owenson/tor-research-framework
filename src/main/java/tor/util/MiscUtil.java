package tor.util;

/**
 * Created by gho on 03/01/15.
 */
public class MiscUtil {
    public static String stringMaxWidth(String input, int width) {
        StringBuilder output = new StringBuilder();
        int max= input.length();
        int i=0;
        for(i=0; i<max; i+=width) {
            output.append(input.subSequence(i, Math.min(i+width,max))+"\n");
        }
        if(i<max)
            output.append(input.subSequence(i, Math.min(i+width,max))+"\n");
        return output.toString().trim();
    }
}
