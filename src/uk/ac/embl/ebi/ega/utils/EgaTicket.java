/*
 * Copyright 2015 EMBL-EBI.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package uk.ac.embl.ebi.ega.utils;

//a.download_ticket, a.file_stable_id, a.file_type, a.encryption_key, a.type, a.target

import java.util.LinkedHashMap;
import java.util.Map;


/**
 *
 * @author asenf
 */
public class EgaTicket implements Comparable {
    private String ticket = null;
    private String label = null;
    private String fileID = null;
    private String fileType = null;
    private String fileSize = null;
    private String fileName = null;
    private String encryptionKey = null;
    private String transferType = null;
    private String transferTarget = null;
    private String user = null;
    
    public EgaTicket() {
        
    }
    
    public EgaTicket(String ticket, String label, String fileID, String fileType, String fileSize, String fileName, String encryptionKey, String transferType, String transferTarget, String user) {
        this.ticket = ticket;
        this.label = label;
        this.fileID = fileID;
        this.fileType = fileType;
        this.fileSize = fileSize;
        this.fileName = fileName;
        this.encryptionKey = encryptionKey;
        this.transferType = transferType;
        this.transferTarget = transferTarget;
        this.user = user;
    }
    
    // -------------------------------------------------------------------------
    // --- Getters and Setters -------------------------------------------------
    // -------------------------------------------------------------------------
    
    public void setTicket(String ticket) {
        this.ticket = ticket;
    }
    
    public void setLabel(String label) {
        this.label = label;
    }

    public void setFileID(String fileID) {
        this.fileID = fileID;
    }

    public void setFileType(String fileType) {
        this.fileType = fileType;
    }

    public void setFileSize(String fileSize) {
        this.fileSize = fileSize;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public void setEncryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
    }
    
    public void setTransferType(String transferType) {
        this.transferType = transferType;
    }

    public void setTransferTarget(String transferTarget) {
        this.transferTarget = transferTarget;
    }
    
    public void setUser(String user) {
        this.user = user;
    }

    public String getTicket() {
        return this.ticket;
    }
    
    public String getLabel() {
        return this.label;
    }

    public String getFileID() {
        return this.fileID;
    }
    
    public String getFileType() {
        return this.fileType;
    }
    
    public String getFileSize() {
        return this.fileSize;
    }

    public String getFileName() {
        return this.fileName;
    }

    public String getEncryptionKey() {
        return this.encryptionKey;
    }
    
    public String getTransferType() {
        return this.transferType;
    }
    
    public String getTransferTarget() {
        return this.transferTarget;
    }
    
    public String getUser() {
        return this.user;
    }
    
    public Map<String,String> getMap() {
        Map<String,String> result = new LinkedHashMap<>();

        result.put("ticket", this.ticket);
        result.put("label", this.label);
        result.put("fileID", this.fileID);
        result.put("fileType", this.fileType);
        result.put("fileSize", this.fileSize);
        result.put("fileName", this.fileName);
        result.put("encryptionKey", this.encryptionKey);
        result.put("transferType", this.transferType);
        result.put("transferTarget", this.transferTarget);
        result.put("user", this.user);
                
        return result;
    }

    @Override
    public int compareTo(Object o) {
        String otherticket = ((EgaTicket)o).getTicket();
        return this.ticket.equals(otherticket)?0:1;
    }
}
