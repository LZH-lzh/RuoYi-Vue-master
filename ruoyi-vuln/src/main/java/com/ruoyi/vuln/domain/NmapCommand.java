package com.ruoyi.vuln.domain;

import java.util.List;

/**
 * @Description: TODO
 * @author: lzh
 * @date: 2022年09月29日 14:46
 */
public class NmapCommand {
    private String uuid;
    private List<String> scriptSelect;
    private boolean checked;
    private String srcIP;
    private String desIP;
    private String output;
    private boolean useFile;
    private String addrFileName;

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

    public List<String> getScriptSelect() {
        return scriptSelect;
    }

    public boolean isChecked() {
        return checked;
    }

    public String getSrcIP() {
        return srcIP;
    }

    public String getDesIP() {
        return desIP;
    }

    public void setScriptSelect(List<String> scriptSelect) {
        this.scriptSelect = scriptSelect;
    }

    public void setChecked(boolean checked) {
        this.checked = checked;
    }

    public void setSrcIP(String srcIP) {
        this.srcIP = srcIP;
    }

    public void setDesIP(String desIP) {
        this.desIP = desIP;
    }

    public boolean isUseFile() {
        return useFile;
    }

    public void setUseFile(boolean useFile) {
        this.useFile = useFile;
    }

    public String getAddrFileName() {
        return addrFileName;
    }

    public void setAddrFileName(String addrFileName) {
        this.addrFileName = addrFileName;
    }

    @Override
    public String toString() {
        return "NmapCommand{" +
                "uuid='" + uuid + '\'' +
                ", scriptSelect=" + scriptSelect +
                ", checked=" + checked +
                ", srcIP='" + srcIP + '\'' +
                ", desIP='" + desIP + '\'' +
                ", output='" + output + '\'' +
                ", useFile=" + useFile +
                ", addrFileName='" + addrFileName + '\'' +
                '}';
    }
}
