package org.apache.hadoop.hbase.security.oauthbearer;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class Utils {
  /**
   *  Converts a {@code Map} class into a string, concatenating keys and values
   *  Example:
   *      {@code mkString({ key: "hello", keyTwo: "hi" }, "|START|", "|END|", "=", ",")
   *          => "|START|key=hello,keyTwo=hi|END|"}
   */
  public static <K, V> String mkString(Map<K, V> map, String begin, String end,
    String keyValueSeparator, String elementSeparator) {
    StringBuilder bld = new StringBuilder();
    bld.append(begin);
    String prefix = "";
    for (Map.Entry<K, V> entry : map.entrySet()) {
      bld.append(prefix).append(entry.getKey()).
        append(keyValueSeparator).append(entry.getValue());
      prefix = elementSeparator;
    }
    bld.append(end);
    return bld.toString();
  }

  /**
   *  Converts an extensions string into a {@code Map<String, String>}.
   *
   *  Example:
   *      {@code parseMap("key=hey,keyTwo=hi,keyThree=hello", "=", ",") => { key: "hey", keyTwo: "hi", keyThree: "hello" }}
   *
   */
  public static Map<String, String> parseMap(String mapStr, String keyValueSeparator, String elementSeparator) {
    Map<String, String> map = new HashMap<>();

    if (!mapStr.isEmpty()) {
      String[] attrvals = mapStr.split(elementSeparator);
      for (String attrval : attrvals) {
        String[] array = attrval.split(keyValueSeparator, 2);
        map.put(array[0], array[1]);
      }
    }
    return map;
  }

  /**
   * Given two maps (A, B), returns all the key-value pairs in A whose keys are not contained in B
   */
  public static <K, V> Map<K, V> subtractMap(Map<? extends K, ? extends V> minuend, Map<? extends K, ? extends V> subtrahend) {
    return minuend.entrySet().stream()
      .filter(entry -> !subtrahend.containsKey(entry.getKey()))
      .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }
}
