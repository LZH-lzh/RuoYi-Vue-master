package com.ruoyi.vuln.domain;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.ruoyi.common.annotation.Excel;
import com.ruoyi.common.core.domain.BaseEntity;

/**
 * 单条地址扫描结果对象 vuln_single_addr_details
 * 
 * @author ruoyi
 * @date 2022-09-25
 */
public class VulnSingleAddrDetails extends BaseEntity
{
    private static final long serialVersionUID = 1L;

    /** ipv6地址主键id */
    private Long ipaddrId;

    /** 探测历史主键id */
    @Excel(name = "探测历史主键id")
    private Long recordsId;

    /** ipv6地址 */
    @Excel(name = "ipv6地址")
    private String ipv6Addr;

    /** 指纹信息 */
    @Excel(name = "指纹信息")
    private String resultDetails;

    public void setIpaddrId(Long ipaddrId) 
    {
        this.ipaddrId = ipaddrId;
    }

    public Long getIpaddrId() 
    {
        return ipaddrId;
    }
    public void setRecordsId(Long recordsId) 
    {
        this.recordsId = recordsId;
    }

    public Long getRecordsId() 
    {
        return recordsId;
    }
    public void setIpv6Addr(String ipv6Addr) 
    {
        this.ipv6Addr = ipv6Addr;
    }

    public String getIpv6Addr() 
    {
        return ipv6Addr;
    }
    public void setResultDetails(String resultDetails) 
    {
        this.resultDetails = resultDetails;
    }

    public String getResultDetails() 
    {
        return resultDetails;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this,ToStringStyle.MULTI_LINE_STYLE)
            .append("ipaddrId", getIpaddrId())
            .append("recordsId", getRecordsId())
            .append("ipv6Addr", getIpv6Addr())
            .append("resultDetails", getResultDetails())
            .toString();
    }
}
