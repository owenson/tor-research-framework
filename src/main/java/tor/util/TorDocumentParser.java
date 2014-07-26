package tor.util;


import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.io.StringReader;
import java.util.Arrays;
import java.util.TreeMap;

/**
 * Created by gho on 25/07/14.
 */
public class TorDocumentParser {
    public TreeMap<String,String> map = new TreeMap<String,String>();

    // prduces a map from a normal tor document, key/value pairs
    // parses block BEGIN-ENDS correctly
    // where same key appears twice, value is the concatenated values with | as a delimiter
    public TorDocumentParser(String doc) throws IOException {
        String curKey = null;
        String curVal = null;
        String lns [] = (String[])IOUtils.readLines(new StringReader(doc)).toArray(new String[0]);

        for (int i = 0; i < lns.length; i++) {
            String ln = lns[i];
            if(ln.equals(""))
                continue;

            String sp[] = ln.split(" ");
            boolean nextBegin = lns.length> i+1 ? lns[i+1].contains("BEGIN"):false;

            if(sp.length == 1 && nextBegin) { // single word and multiline
                // see if next line contains begin
                String key = sp[0], val="";

                i+=2;
                for(; i<lns.length; i++) {
                    if(lns[i].contains("END")) {
                        break;
                    }
                    val += lns[i];
                }
                addItem(key, val);
            } else if(sp.length == 1) { // single word but not multiline
                addItem(sp[0], "");
            }
            else { // regular line
                addItem(sp[0], StringUtils.join(Arrays.copyOfRange(sp, 1, sp.length), " "));
            }


        }

//        for (String k : map.keySet()) {
//            System.out.println(k + "|||= " + map.get(k));
//        }
    }

    public void addItem(String k, String v) {
        if(!map.containsKey(k))
            map.put(k, v);
        else {
            map.put(k, map.get(k)+ "|" + v);
        }
    }

    public String[] getArrayItem(String k) {
        String s[] = map.get(k).split("\\|");
        if(s.length < 2)
            throw new RuntimeException("error - not array item");
        return s;
    }

    public String getItem(String k) {
        return map.get(k);
    }
}
