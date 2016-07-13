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

package uk.ac.embl.ebi.ega.direct;

import org.bouncycastle.util.Arrays;
import uk.ac.embl.ebi.ega.egaapiwrapper.EgaAPIWrapper;
import uk.ac.embl.ebi.ega.utils.EgaFile;
import uk.ac.embl.ebi.ega.utils.EgaTicket;

/**
 *
 * @author asenf
 */
public class testMe {
    private EgaAPIWrapper api;
    private boolean login = false;
    
    public testMe(String username, String password) {
        
        this.api = new EgaAPIWrapper("ega.ebi.ac.uk", "ega.ebi.ac.uk", true);
        login = this.api.login(username, password.toCharArray());
        System.out.println("Login Success? " + login);
    }
    
    void test() {
        if (!login)
            return;
        
        // NOT Currently Set Up for Local EGA Testing!
        
        System.out.println("Commencing Tests");
        
        // Test 0: Test my IP
        System.out.println("IP Check");
        String ip = this.api.myIP();
        System.out.println("IP is: " + ip);
        
        // Test 1: Get Dataset
        System.out.println("Listing Datasets");
        String[] listDatasets = this.api.listDatasets();
        System.out.println(listDatasets.length + " datasets retrieved.");

        // Test 2: Get Files for Datasets
        String oneFile = null;
        System.out.println("\nListing Files:\n");
        System.out.println("Listing Dataset Files");        
        int limit = 50;
        if (listDatasets != null) {
            for (String dataset : listDatasets) {
                //if (limit-- <= 0) break;
                // Print first 5 files
                long time = System.currentTimeMillis();
                EgaFile[] listDatasetFiles = this.api.listDatasetFiles(dataset);
                time = System.currentTimeMillis() - time;
                if (listDatasetFiles!=null && listDatasetFiles.length>0) {
                    System.out.println("Dataset: " + dataset + "\t(" + time + "ms)");
                    for (int j=0; j<(listDatasetFiles.length>5?5:listDatasetFiles.length); j++) {
                        try {
                            System.out.println("   " + j + ": " + 
                                    listDatasetFiles[j].getFileName() + " :: " + 
                                    listDatasetFiles[j].getFileSize() + " :: " + 
                                    listDatasetFiles[j].getStatus());
                        } catch (Throwable t) {
                            System.out.println("Thrown: " + t.getMessage());
                        }
                        if ((oneFile==null || oneFile.length()==0) && (listDatasetFiles[j]!=null))
                            oneFile = listDatasetFiles[j].getFileID();
                    }
                } else {
                    System.out.println("Dataset: " + dataset + "\t(" + time + "ms)");
                    System.out.println("   : --"); 
                    
                }
                try {Thread.sleep(600);} catch (InterruptedException ex) {;}
            }
        }
        
        // Test 2.5: List one specific file information
        if (oneFile!=null && oneFile.length()>0) {
            System.out.println("\nListing one file:\n");
            
            EgaFile[] oneDatasetFiles = this.api.listFileInfo(oneFile);
            if (oneDatasetFiles!=null && oneDatasetFiles.length>0) {
                System.out.println("File info: " + oneFile);
                System.out.println("   " + 0 + ": " + 
                            oneDatasetFiles[0].getFileName() + " :: " + 
                            oneDatasetFiles[0].getFileSize() + " :: " + 
                            oneDatasetFiles[0].getStatus());
            }
        }
        
        // Test 3: Request a Dataset
        System.out.println("\nRequesting one dataset:\n");
        String[] requestDatasetByID = this.api.requestByID("EGAD00010000498", "dataset", "abc", "apiTest");
        if (requestDatasetByID!=null && requestDatasetByID.length > 0)
            System.out.println(requestDatasetByID[0] + " files requested.");

        // Test 4: Request a File
        System.out.println("\nRequesting one file:\n");
        String[] requestFiletByID = this.api.requestByID("EGAF00000621230", "file", "abc", "apiTest");
        if (requestFiletByID!=null && requestFiletByID.length > 0)
            System.out.println(requestFiletByID[0] + " files requested.");

        // Test 4.5: List all Requests
        System.out.println("\nListing All Requests (Light):\n");
        String[] listAllRequestsLight = this.api.listAllRequestsLight();
        System.out.println("---" + listAllRequestsLight.length);
        if (listAllRequestsLight!=null) {
            for (int i=0; i<listAllRequestsLight.length; i++)
                System.out.println(" :light: " + listAllRequestsLight[i]);
        }
        
        for (int ii=0; ii<10; ii++) {
        // Test 5: List all Requests
        System.out.println("\nListing All Requests:\n");
        EgaTicket[] listAllRequests = this.api.listAllRequests();
        System.out.println("---" + (listAllRequests!=null?listAllRequests.length:"NULL"));
//        if (listAllRequests!=null) {
//            for (int i=0; i<listAllRequests.length; i++)
//                System.out.println(" :all: " + listAllRequests[i].getLabel() + "  " + listAllRequests[i].getTicket() +
//                        "  " + listAllRequests[i].getFileName());
//        }
        }
        
        // Test 6: List one Requests
        System.out.println("\nListing One Request:\n");
        String ticket = "";
        EgaTicket[] listRequest = this.api.listRequest("apiTest");
        if (listRequest!=null) {
            for (int i=0; i<listRequest.length; i++) {
                System.out.println(" :one: " + listRequest[i].getLabel() + "  " + listRequest[i].getTicket());
                if (ticket.length() == 0)
                    ticket = listRequest[i].getTicket();
            }
        }
        
        // Test 7: List details of one ticket of that request
        System.out.println("\nTicket Details:\n");
        String requestdeleteticket = "";
        EgaTicket[] listRequestDetails = this.api.listTicketDetails(ticket);
        if (listRequestDetails!=null && listRequestDetails.length > 0) {
            System.out.println("    " + listRequestDetails[0].getTicket());
            System.out.println("    " + listRequestDetails[0].getFileName());
            System.out.println("    " + listRequestDetails[0].getFileSize());
            requestdeleteticket = listRequestDetails[0].getLabel();
        } else
            System.out.println("No Info...");

        // Test 7.1 Delete one ticket
        System.out.println("\nDelete one Ticket:\n");
        String[] delete_ticket = this.api.delete_ticket(requestdeleteticket, ticket);
        for (int i=0; i<delete_ticket.length; i++)
            System.out.println(delete_ticket[i]);
        
        // Test 8: Delete a Request
        System.out.println("\nDeleting One Request:\n");
        String[] delete_request = this.api.delete_request("apiTest");
        if (delete_request!=null && delete_request.length > 0)
            System.out.println("Deleted. " + delete_request.length);
        
            // Test 8: Download a File
            //this.api.setUdt(true);
//        System.out.println("Downloading a File");
//        String[] download_netty = this.api.download_netty(t, "_ega-box-81_8622007039_R06C02_Red.idat.cip", "");
//        for (String result : download_netty)
//            System.out.println(result);

        // Test 9: Metadata Download
        System.out.println("\nDownloading metadata for EGAD00001001464:\n");
        String[] download_metadata = this.api.download_metadata("EGAD00001001464");
        if (download_metadata!=null && download_metadata.length > 0) {
            System.out.println("Downloaded. " + download_metadata.length);
            for (String x : download_metadata)
                System.out.println(" -- " + x);
        }
        
        // Done - log out again
        System.out.println("\nLogging out:\n");
        this.api.logout();
        this.login = false;
    }
    
    private void timeout_test(String username, String password) {
        if (!login) {
            this.api = this.api==null?new EgaAPIWrapper("ega.ebi.ac.uk", "ega.ebi.ac.uk", true):this.api;
            login = this.api.login(username, password.toCharArray());
            System.out.println("Login Success? " + login);
        }
        if (!login)
            return;
        
        // Listing Datasets
        System.out.println("Listing Datasets");
        String[] listDatasets = this.api.listDatasets();
        System.out.println(listDatasets.length + " datasets retrieved.");
        System.out.println("Listing Datasets");
        String[] listDatasets_ = this.api.listDatasets();
        System.out.println(listDatasets_.length + " datasets retrieved.");
        
        // Waiting 11 Minutes
        System.out.println("Waiting for 11 minutes (session timeout is 10 minutes)");
        long eleven = 1000 * 60 * 11;
        try {
            Thread.sleep(eleven);
        } catch (InterruptedException ex) {;}
        
        // Listing Datasets again
        System.out.println("Listing Datasets Again");
        String[] listDatasets_after = this.api.listDatasets();
        System.out.println(listDatasets_after.length + " record retrieved.");
        
        // Compare results...
        boolean works = Arrays.areEqual(listDatasets, listDatasets_after);
        System.out.println("Same? " + works);

        for (int i=0; i<listDatasets_after.length; i++)
            System.out.println("   " + listDatasets_after[i]); // timeout message
        
        // Listing Datasets again
        System.out.println("Listing Datasets Yet Again");
        String[] listDatasets_after_again = this.api.listDatasets();
        
        // Logout - session already expired. This is to test no Nullpointer error is thrown
        this.api.logout();
    }    
    
    private void special_test() {
        if (!login)
            return;
        
        System.out.println("Commencing Special Tests");
        
        // Test 0: Test my IP
        System.out.println("IP Check");
        String ip = this.api.myIP();
        System.out.println("IP is: " + ip);
        
        // Test 1: Get Dataset
        //System.out.println("Listing Datasets");
        //String[] listDatasets = this.api.listDatasets();
        //System.out.println(listDatasets.length + " datasets retrieved.");
        String[] listDatasets = {"EGAD00001000870"};

        // Test 2: Get Files for Datasets
        String oneFile = null;
        System.out.println("\nListing Files:\n");
        System.out.println("Listing Dataset Files");        
        if (listDatasets != null) {
            for (String dataset : listDatasets) {
                EgaFile[] listDatasetFiles = this.api.listDatasetFiles(dataset);
                if (listDatasetFiles!=null && listDatasetFiles.length>0) {
                    System.out.println("Dataset: " + dataset);
                    for (int j=0; j<listDatasetFiles.length; j++) {
                        try {
                            System.out.println("   " + j + ": " + 
                                    listDatasetFiles[j].getFileName() + " :: " + 
                                    listDatasetFiles[j].getFileSize() + " :: " + 
                                    listDatasetFiles[j].getStatus());
                        } catch (Throwable t) {
                            System.out.println(t.getMessage());
                        }
                        if ((oneFile==null || oneFile.length()==0) && (listDatasetFiles[j]!=null))
                            oneFile = listDatasetFiles[j].getFileID();
                    }
                }
            }
        }
        
    }
    
    public static void main(String[] args) {

        testMe x = new testMe(args[0], args[1]);
        
        //x.special_test();;
        
        System.out.println("Main Tests:");
        for (int i=0; i<100; i++)
            x.test();
        System.out.println("Session Timeout Tests:");
        x.timeout_test(args[0], args[1]);
        
    }
}
