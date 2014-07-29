/*
        Tor Research Framework - easy to use tor client library/framework
        Copyright (C) 2014  Dr Gareth Owen <drgowen@gmail.com>
        www.ghowen.me / github.com/drgowen/tor-research-framework

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
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

    // the order of the IPv4 accept/reject exit policies matters, and this order is destroyed by the parser
    // we therefore substitute a synthesised key for accept/reject lines ("ipv4-policy" like the ipv6-policy key),
    // and we prepend accept or reject to each line, using space as a second-level separator
    // i.e. accept 80|reject *:*
    public final static String IPv4PolicyKey = "ipv4-policy";

    private static TreeMap<String,String> keyReplacementMap;

    public TreeMap<String,String> KeyReplacementMap() {
        if (keyReplacementMap == null) {
            keyReplacementMap = new TreeMap<String,String>();
            keyReplacementMap.put("accept", IPv4PolicyKey);
            keyReplacementMap.put("reject", IPv4PolicyKey);
        }
        return keyReplacementMap;
    }

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
        // keys in the replacement map are replaced by the corresponding key in the map
        // the original key is prepended to the value, separated by a space
        if (KeyReplacementMap().containsKey(k)) {
            addItem(KeyReplacementMap().get(k), k + " " + v);
        } else {
            if (!map.containsKey(k))
                map.put(k, v);
            else {
                map.put(k, map.get(k) + "|" + v);
            }
        }
    }

    public String[] getArrayItem(String k) {
        // keys in the replacement map are replaced by the corresponding key in the map
        if (KeyReplacementMap().containsKey(k)) {
            return getArrayItem(KeyReplacementMap().get(k));
        } else {
            String s[] = map.get(k).split("\\|");
            if (s.length < 2)
                throw new RuntimeException("error - not array item");
            return s;
        }
    }

    public String getItem(String k) {
        // keys in the replacement map are replaced by the corresponding key in the map
        if (KeyReplacementMap().containsKey(k))
            return getItem(KeyReplacementMap().get(k));
        else
            return map.get(k);
    }
}
