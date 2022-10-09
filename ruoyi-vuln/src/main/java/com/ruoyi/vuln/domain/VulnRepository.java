package com.ruoyi.vuln.domain;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.ruoyi.common.annotation.Excel;
import com.ruoyi.common.core.domain.BaseEntity;

/**
 * 漏洞库对象 vuln_repository
 * 
 * @author IPv6ScanGroup
 * @date 2022-10-05
 */
public class VulnRepository extends BaseEntity
{
    private static final long serialVersionUID = 1L;

    /** 脚本库主键 */
    private Long scriptId;

    /** 脚本名称 */
    @Excel(name = "脚本名称")
    private String scriptName;

    /** 脚本描述 */
    @Excel(name = "脚本描述")
    private String scriptDescription;

    public void setScriptId(Long scriptId) 
    {
        this.scriptId = scriptId;
    }

    public Long getScriptId() 
    {
        return scriptId;
    }
    public void setScriptName(String scriptName) 
    {
        this.scriptName = scriptName;
    }

    public String getScriptName() 
    {
        return scriptName;
    }
    public void setScriptDescription(String scriptDescription) 
    {
        this.scriptDescription = scriptDescription;
    }

    public String getScriptDescription() 
    {
        return scriptDescription;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this,ToStringStyle.MULTI_LINE_STYLE)
            .append("scriptId", getScriptId())
            .append("scriptName", getScriptName())
            .append("scriptDescription", getScriptDescription())
            .toString();
    }
}
