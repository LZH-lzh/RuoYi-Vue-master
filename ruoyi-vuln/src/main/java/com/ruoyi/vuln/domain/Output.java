package com.ruoyi.vuln.domain;

/**
 * @Description: TODO
 * @author: lzh
 * @date: 2022年10月05日 9:03
 */
public class Output {
    private String uuid;
    private String msg;
    public Output(String uuid,String msg){
        this.uuid = uuid;
        this.msg = msg;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    @Override
    public String toString() {
        return "Output{" +
                "uuid='" + uuid + '\'' +
                ", msg='" + msg + '\'' +
                '}';
    }
}
