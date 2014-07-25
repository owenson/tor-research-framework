package tor.util;


import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.StringReader;
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
        for(Object ln : IOUtils.readLines(new StringReader(doc))) {
            if(((String)ln).equals(""))
                continue;

            String sp[] = ((String)ln).split(" ");
            if(curKey != null && sp[0].indexOf("BEGIN")!=-1)
                continue;
            else if(curKey != null && sp[0].indexOf("END")!=-1) {
                addItem(curKey, curVal);
                curKey = null;
                curVal = null;
                continue;
            } else if(curKey != null) {
                curVal += (String)ln;
                continue;
            }
            else if(sp.length >= 2) {
                addItem(sp[0], sp[1]);
            } else {
                curKey = sp[0];
                curVal = "";
            }
        }
        for (String k : map.keySet()) {
            System.out.println(k + "|||= " + map.get(k));
        }
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
