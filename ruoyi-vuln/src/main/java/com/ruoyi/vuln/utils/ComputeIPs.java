package com.ruoyi.vuln.utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * @Description: TODO
 * @author: lzh
 * @date: 2022年10月06日 19:36
 */
public class ComputeIPs {
    /*public static void main(String[] args) {
        String ipBegin = "10.10.9.0";
        String ipEnd = "10.10.10.255";
        List<String> iPs = findIPsForIpv4(ipBegin, ipEnd);

    }*/

    /**
     * 查找两个IP地址之间的IP ipv6
     * @param startIp
     * @param endIp
     * @return
     */
    public static List<String> findIPsForIpv6(String startIp, String endIp) {
        BigInteger startNumber = ipv6ToNumber(startIp);
        BigInteger endNumber = ipv6ToNumber(endIp).add(BigInteger.valueOf(1));
        List<String> ips = new ArrayList<String>();
        while (startNumber.compareTo(endNumber) < 0) {
            ips.add(numberToIpv6(startNumber));
            ips.add(" ");//本项目需要每个地址间隔开
            startNumber = startNumber.add(BigInteger.valueOf(1));
        }
        return ips;
    }

    /**
     * 查找两个IP地址之间的IP ipv4
     * @param startIp
     * @param endIp
     * @return
     */
    public static List<String> findIPsForIpv4(String startIp, String endIp) {
        long startNumber = ipv4ToNumber(startIp);
        long endNumber = ipv4ToNumber(endIp) + 1;
        List<String> ips = new ArrayList<String>();

        for (long i = startNumber; i < endNumber; i++) {
            ips.add(numberToIpv4(i));
        }
        return ips;
    }

    /**
     * IPv6地址转换成数字
     * @param ip
     * @return
     */
    public static BigInteger ipv6ToNumber(String ip) {
        String[] ips = ip.split(":");
        BigInteger rs = new BigInteger("0");

        for (int i = 0; i < ips.length; i++) {
            BigInteger a = BigInteger.valueOf(Integer.parseInt(ips[i], 16));
            BigInteger b = BigInteger.valueOf(65536).pow(7 - i);
            BigInteger c = a.multiply(b);
            rs = rs.add(c);
        }
        return rs;
    }

    /**
     * 数字转换成IPV6地址
     * @param number
     * @return
     */
    public static String numberToIpv6(BigInteger number) {
        String ip = "";
        List<String> ips = new ArrayList<String>();

        for (int i = 0; i < 8; i++) {
            ips.add(Integer.toHexString(number.divideAndRemainder(BigInteger.valueOf(65536))[1].intValue()));
            number = number.shiftRight(16);
        }

        for (int i = ips.size() - 1; i >= 0; i--) {
            ip = ip.concat(ips.get(i));
            if (i > 0) {
                ip = ip.concat(":");
            }
        }
        return ip;
    }
    /**
     * 数字转换成IPv4地址
     * @param number
     * @return
     */
    public static String numberToIpv4(long number) {
        String ip = "";
        List<String> ips = new ArrayList<String>();
        for (int i = 0; i < 4; i++) {
            ips.add(String.valueOf(number % 256));
            number = number >> 8;
        }
        for (int i = ips.size() - 1; i >= 0; i--) {
            ip = ip.concat(ips.get(i));
            if (i > 0) {
                ip = ip.concat(".");
            }
        }
        return ip;
    }
    /**
     * IPv4地址转换成数字
     * @param ip
     */
    public static long ipv4ToNumber(String ip) {
        long rs = 0;
        if (ip == null || ip.isEmpty()) {
            return rs;
        }
        String[] ips = ip.split("\\.");
        for (int i = 0; i < ips.length; i++) {
            rs += Integer.parseInt(ips[i]) * Math.pow(256, (3 - i));
        }
        return rs;
    }
}
