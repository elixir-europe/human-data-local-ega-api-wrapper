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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 * @author asenf
 */
public class EgaFile {
    private String fileid = null;
    private String filename = null;
    private String indexname = null;
    private String dataset = null;
    private long size = -1;
    private String MD5 = null;
    private String status = null;
    
    public EgaFile() {
        
    }
    
    public EgaFile(String fileid, String filename, String indexname, String dataset, long size, String MD5, String status) {
        this.fileid = fileid;
        this.filename = filename;
        this.indexname = indexname;
        this.dataset = dataset;
        this.size= size;
        this.MD5 = MD5;
        this.status = status;
    }
    
    // -------------------------------------------------------------------------
    // --- Getters and Setters -------------------------------------------------
    // -------------------------------------------------------------------------

    public void setFileID(String fileid) {
        this.fileid = fileid;
    }
    
    public void setFileName(String filename) {
        this.filename = filename;
    }

    public void setFileIndex(String indexname) {
        this.indexname = indexname;
    }
    
    public void setFileDataset(String dataset) {
        this.dataset = dataset;
    }
    
    public void setFileSize(long size) {
        this.size = size;
    }
    
    public void setMD5(String MD5) {
        this.MD5 = MD5;
    }

    public void setFileStatus(String status) {
        this.status = status;
    }
    
    public String getFileID() {
        return this.fileid;
    }
    
    public String getFileName() {
        return this.filename;
    }

    public String getFileIndex() {
        return this.indexname;
    }
    
    public String getFileDataset() {
        return this.dataset;
    }

    public long getFileSize() {
        return this.size;
    }
    
    public String getMD5() {
        return this.MD5;
    }

    public String getStatus() {
        return this.status;
    }

    public Map<String,String> getMap() {
        Map<String,String> result = new LinkedHashMap<>();

        result.put("fileID", this.fileid);
        result.put("fileName", this.filename);
        result.put("fileIndex", this.indexname);
        result.put("fileDataset", this.dataset);
        result.put("fileSize", String.valueOf(this.size));
        result.put("fileMD5", this.MD5);
        result.put("fileStatus", this.status);
                
        return result;
    }
}
