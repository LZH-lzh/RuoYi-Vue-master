package com.ruoyi.vuln.service.impl;

import com.ruoyi.vuln.commandobserver.CommandExecutorObserver;
import com.ruoyi.vuln.commandsubject.CommandExecutorSubject;
import com.ruoyi.vuln.domain.NmapCommand;
import com.ruoyi.vuln.domain.VulnDetectHistory;
import com.ruoyi.vuln.domain.vo.ExecutionObjectFactory;
import com.ruoyi.vuln.domain.vo.Script;
import com.ruoyi.vuln.domain.vo.ScriptHelp;
import com.ruoyi.vuln.mapper.VulnDetectHistoryMapper;
import com.ruoyi.vuln.service.INmapExecutor;
import com.ruoyi.vuln.utils.ComputeIPs;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import java.io.*;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @Description: TODO
 * @author: lzh
 * @date: 2022年09月25日 14:24
 */
@Service
public class INmapExecutorImpl implements INmapExecutor, CommandExecutorSubject {
    private Thread commandThread;
    //private NmapCommand cmd;
    public List<String> addrFileList = new ArrayList<>();
    @Autowired
    private VulnDetectHistoryMapper vulnDetectHistoryMapper;
    /*
     *  执行nmap命令
     *  @param nmapCommand nmap命令
     * */
    @Override
    public void nmapExecute(NmapCommand nmapCommand) {
        try {
            String command = composeCommand(nmapCommand);
            Process p = Runtime.getRuntime().exec(command);
            final InputStream stream = p.getInputStream();
            final InputStream errors = p.getErrorStream();
            commandThread = new Thread(new Runnable() {
                public void run() {
                    BufferedReader reader = null;
                    BufferedReader errorReader = null;
                    String s = "", line = null;
                    try {
                        boolean firstLine = true;
                        reader = new BufferedReader(new InputStreamReader(stream, Charset.forName("GBK")));
                        while ((line = reader.readLine()) != null) {
                            line = escape(line);
                            String jump = "<br>";
                            if (firstLine)
                                jump = "";
                            s = s + jump + line;
                            firstLine = false;
                        }
                        errorReader = new BufferedReader(new InputStreamReader(errors));
                        while ((line = errorReader.readLine()) != null) {
                            line = escape(line);
                            String jump = "<br>";
                            if (firstLine)
                                jump = "";
                            s = s + jump + line;
                            firstLine = false;
                        }
                        System.out.println("扫描结果---------：" + s);
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        String finalCommand = "";
                        //下面是构建最终要显示的命令
                        if (nmapCommand.isChecked()) {     //如果脚本全选
                            if (nmapCommand.isUseFile()) {//如果使用文件输入地址
                                finalCommand = "nmap " + "-6 " + "--script " + "\"vuln\" " + nmapCommand.getAddrFileName();
                            } else {                      //如果不使用文件输入地址
                                finalCommand = "nmap " + "-6 " + "--script " + "\"vuln\" " + nmapCommand.getSrcIP() + "------>" + nmapCommand.getDesIP();
                            }
                        } else {                            //如果不全选脚本
                            if (nmapCommand.isUseFile()) {//如果使用文件输入地址
                                String[] outs = nmapCommand.getScriptSelect().toArray(new String[]{});//把传过来的选择的脚本加到命令中
                                StringBuilder outss = new StringBuilder();
                                for (String s1 : outs) {
                                    outss.append(s1);
                                }
                                finalCommand = "nmap " + "-6 " + "--script " + "\" " + outss + "\" " + nmapCommand.getAddrFileName();
                            } else {                      //如果不使用文件输入地址
                                String[] outs = nmapCommand.getScriptSelect().toArray(new String[]{});//把传过来的选择的脚本加到命令中
                                StringBuilder outss = new StringBuilder();
                                for (String s1 : outs) {
                                    outss.append(s1);
                                }
                                finalCommand = "nmap " + "-6 " + "--script " + "\" " + outss + "\" " + nmapCommand.getSrcIP() + "------>" + nmapCommand.getDesIP();
                            }
                        }
                        nmapCommand.setOutput(finalCommand + "<br><br>" + s);
                        notifyObserves(nmapCommand);
                        if (reader != null) {
                            try {
                                reader.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                                notifyObserves(nmapCommand);
                            }
                        }
                        //下面是将本次扫描记录添加到数据库
                        VulnDetectHistory his = new VulnDetectHistory();
                        his.setCommand(finalCommand);
                        his.setRecordsId(Long.valueOf(nmapCommand.getUuid()));
                        Date d = new Date();
                        //SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                        his.setScanDatetime(d);
                        his.setHighriskRate("未知");
                        his.setTargetRange(nmapCommand.getSrcIP() + "------>" + nmapCommand.getDesIP());
                        his.setResults(s);
                        insertVulnDetectHistory(his);
                    }
                }
            });
            commandThread.start();
            commandThread.join();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    /*
     *  初始化nmap脚本
     *  @return 脚本列表
     * */
    @Override
    public List<String> nmapInitScript() {
        Object lock = new Object();//任何一个对象都能当锁
        List<String> vulnList = new ArrayList<>();
        Boolean flag = false;
        //XML文件由Nmap程序输出
        try {
            //Process p = Runtime.getRuntime().exec("nmap --script-help all -oX F:\\NmapTemp\\44.xml --webxml");
            /*commandThread = new Thread(new Runnable() {
                public void run() {

                }
            });*/
            StringBuilder sb = new StringBuilder();
            try {
                BufferedReader br = new BufferedReader(new FileReader("F:\\NmapTemp\\44.xml"));
                String sCurrentLine;
                while ((sCurrentLine = br.readLine()) != null) {
                    sb.append(sCurrentLine);
                }
                JAXBContext jaxbContext = JAXBContext.newInstance(ExecutionObjectFactory.class);
                Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
                StringReader reader = new StringReader(sb.toString());
                Object execution = unmarshaller.unmarshal(reader);
                if (execution instanceof ScriptHelp) {
                    ScriptHelp sh = (ScriptHelp) execution;
                    List<Script> list = sh.getScripts();
                    Iterator<Script> iterator = list.iterator();
                    while (iterator.hasNext()) {
                        Script script = iterator.next();
                        if (script.getCategories().contains("vuln")) {
                            //正则表达式取出脚本名称
                            String[] sl = script.getFilename().split("scripts\\\\");
                            String[] ll = sl[1].split("\\.");
                            vulnList.add(ll[0]);
                        }
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return vulnList;
    }

    /*
     *  通过nmapCommand构造完整的nmap命令
     * */
    @Override
    public String composeCommand(NmapCommand nmapCommand) {
        boolean a = false;
        List<String> iPs = new ArrayList<>();
        if (nmapCommand.getDesIP() != null && nmapCommand.getDesIP().length() != 0) {
            a = true;
            iPs = ComputeIPs.findIPsForIpv6(nmapCommand.getSrcIP(), nmapCommand.getDesIP());
        }
        List<String> commandList = new ArrayList<String>();
        commandList.add("nmap ");
        commandList.add("-6 ");
        commandList.add("--script ");
        if (nmapCommand.isChecked()) {
            commandList.add("\"vuln\" ");
            if (nmapCommand.isUseFile()) {
                commandList.addAll(addrFileList);
            } else {
                if (a) {
                    commandList.addAll(iPs);
                } else {
                    commandList.add(nmapCommand.getSrcIP());
                }
            }
            String[] s = commandList.toArray(new String[]{});
            StringBuilder commandstr = new StringBuilder();
            for (String s1 : s) {
                System.out.print(s1);
                commandstr.append(s1);
            }
            return commandstr.toString();
        }
        commandList.add("\"");
        for (String o : nmapCommand.getScriptSelect()) {
            commandList.add(o);
            commandList.add(",");
        }
        commandList.add("\" ");
        if (nmapCommand.isUseFile()) {
            commandList.addAll(addrFileList);
        } else {
            if (a) {
                commandList.addAll(iPs);
            } else {
                commandList.add(nmapCommand.getSrcIP());
            }
        }
        String[] s = commandList.toArray(new String[]{});
        StringBuilder commandstr = new StringBuilder();
        for (String s1 : s) {
            //System.out.print(s1);
            commandstr.append(s1);
        }
        return commandstr.toString();

    }

    @Transactional
    @Override
    public int insertVulnDetectHistory(VulnDetectHistory vulnDetectHistory) {
        int rows = vulnDetectHistoryMapper.insertVulnDetectHistory(vulnDetectHistory);
        //insertVulnSingleAddrDetails(vulnDetectHistory);
        return rows;
    }

    @Override
    public List<String> handleFile(MultipartFile file) throws IOException {
        List<String> addrList = new ArrayList<>();
        InputStream inputStream = file.getInputStream();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            addrList.add(line);
            addrList.add(" ");
        }
        addrFileList = addrList;
        return addrList;
    }

    private String escape(String str) {
        String line = str;
        line = line.replace("&", "&amp;");
        line = line.replace("\"", "&quot;");
        line = line.replace("<", "&lt;");
        line = line.replace(">", "&gt;");
        return line;
    }


    @Override
    public void addObserver(CommandExecutorObserver observer) {
        observers.add(observer);
    }

    @Override
    public void removeObserver(CommandExecutorObserver observer) {
        observers.remove(observer);
    }

    @Override
    public void notifyObserves(NmapCommand nmapCommand) {
        for (CommandExecutorObserver observer : observers) {
            observer.update(nmapCommand);
        }
    }
}
