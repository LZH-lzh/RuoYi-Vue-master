package com.ruoyi.vuln.service;

import com.ruoyi.vuln.domain.NmapCommand;
import com.ruoyi.vuln.domain.VulnDetectHistory;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface INmapExecutor {
    /*
    *  执行nmap命令
    *  @param nmapCommand nmap命令
    * */
    public void nmapExecute(NmapCommand nmapCommand);
    /*
    *  初始化nmap脚本
    *  @return 脚本列表
    * */
    public List<String> nmapInitScript();
    /*
    *  通过nmapCommand构造完整的nmap命令
    * */
    public String composeCommand(NmapCommand nmapCommand);
    /**
     * 新增漏洞扫描历史记录
     *
     * @param vulnDetectHistory 漏洞扫描历史记录
     * @return 结果
     */
    public int insertVulnDetectHistory(VulnDetectHistory vulnDetectHistory);
    public List<String> handleFile(MultipartFile file) throws IOException;
}
