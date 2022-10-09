package com.ruoyi.vuln.domain;

import java.util.List;
import java.util.Date;
import com.fasterxml.jackson.annotation.JsonFormat;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.ruoyi.common.annotation.Excel;
import com.ruoyi.common.core.domain.BaseEntity;

/**
 * 漏洞扫描历史记录对象 vuln_detect_history
 * 
 * @author ruoyi
 * @date 2022-09-25
 */
public class VulnDetectHistory extends BaseEntity
{
    private static final long serialVersionUID = 1L;

    /** 探测历史主键id */
    private Long recordsId;

    /** nmap命令 */
    @Excel(name = "nmap命令")
    private String command;

    /** 靶机地址（范围） */
    @Excel(name = "靶机地址", readConverterExp = "范=围")
    private String targetRange;

    /** 扫描时间 */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @Excel(name = "扫描时间", width = 30, dateFormat = "yyyy-MM-dd HH:mm:ss")
    private Date scanDatetime;

    /** 高危漏洞比例 */
    @Excel(name = "高危漏洞比例")
    private String highriskRate;

    /** 高危漏洞比例 */
    @Excel(name = "扫描结果")
    private String results;



    /** 单条地址扫描结果信息 */
    private List<VulnSingleAddrDetails> vulnSingleAddrDetailsList;

    public void setRecordsId(Long recordsId) 
    {
        this.recordsId = recordsId;
    }

    public Long getRecordsId() 
    {
        return recordsId;
    }
    public void setCommand(String command) 
    {
        this.command = command;
    }

    public String getCommand() 
    {
        return command;
    }
    public void setTargetRange(String targetRange) 
    {
        this.targetRange = targetRange;
    }

    public String getTargetRange() 
    {
        return targetRange;
    }
    public void setScanDatetime(Date scanDatetime) 
    {
        this.scanDatetime = scanDatetime;
    }

    public Date getScanDatetime() 
    {
        return scanDatetime;
    }
    public void setHighriskRate(String highriskRate) 
    {
        this.highriskRate = highriskRate;
    }

    public String getHighriskRate() 
    {
        return highriskRate;
    }

    public String getResults() {
        return results;
    }

    public void setResults(String results) {
        this.results = results;
    }

    public List<VulnSingleAddrDetails> getVulnSingleAddrDetailsList()
    {
        return vulnSingleAddrDetailsList;
    }

    public void setVulnSingleAddrDetailsList(List<VulnSingleAddrDetails> vulnSingleAddrDetailsList)
    {
        this.vulnSingleAddrDetailsList = vulnSingleAddrDetailsList;
    }

    @Override
    public String toString() {
        return "VulnDetectHistory{" +
                "recordsId=" + recordsId +
                ", command='" + command + '\'' +
                ", targetRange='" + targetRange + '\'' +
                ", scanDatetime=" + scanDatetime +
                ", highriskRate='" + highriskRate + '\'' +
                ", results='" + results + '\'' +
                ", vulnSingleAddrDetailsList=" + vulnSingleAddrDetailsList +
                '}';
    }
}
