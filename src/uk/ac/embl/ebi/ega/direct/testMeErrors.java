/*
 * Copyright 2016 EMBL-EBI.
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

import uk.ac.embl.ebi.ega.egaapiwrapper.EgaAPIWrapper;
import uk.ac.embl.ebi.ega.utils.EgaFile;

/**
 *
 * @author asenf
 */
public class testMeErrors {
    private EgaAPIWrapper api;
    private boolean login = false;

    public testMeErrors(String username, String password) {
        
        this.api = new EgaAPIWrapper("ega.ebi.ac.uk", "ega.ebi.ac.uk", true);
        login = this.api.login(username, password.toCharArray());
        System.out.println("Login Success? " + login);
    }
    
    private void test() {
        if (!login)
            return;
        
        // Not Currently set up for Local EGA Testing
        
        System.out.println("Commencing Tests");
        
        // Test 0: Test my IP
        System.out.println("IP Check");
        String ip = this.api.myIP();
        System.out.println("IP is: " + ip);
        
        // Test 1: List Dataset Files w/o Permissions
        System.out.println("Test 1: List Dataset Files w/o Permission");
        EgaFile[] lDF = this.api.listDatasetFiles("EGAD00010000819");
        System.out.println("Result? " + (lDF!=null));
        if (lDF!=null) {
            for (EgaFile x:lDF)
                System.out.println("\t" + x.getFileName());
        }

        // Test 2: List Dataset Files w/o Permissions
        System.out.println("Test 2: List File w/o Permission");
        EgaFile[] lFI = this.api.listFileInfo("EGAF00000882757");
        System.out.println("Result? " + (lFI!=null));
        if (lFI!=null) {
            for (EgaFile x:lFI)
                System.out.println("\t" + x.getFileName());
        }

        // Test 3: Request File w/o Permissions
        System.out.println("Test 3: Request File w/o Permission");
        String[] rBIDF = this.api.requestByID("EGAF00000882755", "file", "abc", "_test2");
        System.out.println("Result? " + (rBIDF!=null));
        if (rBIDF!=null) {
            for (String x:rBIDF)
                System.out.println("\t" + x);
        }

        // Test 4: Request Dataset w/o Permissions
        System.out.println("Test 4: Request Dataset w/o Permission");
        String[] rBIDD = this.api.requestByID("EGAD00010000819", "dataset", "abc", "_test3");
        System.out.println("Result? " + (rBIDD!=null));
        if (rBIDD!=null) {
            for (String x:rBIDD)
                System.out.println("\t" + x);
        }
        
        // Done - log out again
        System.out.println("\nLogging out:\n");
        this.api.logout();
        this.login = false;
    }
    
    public static void main(String[] args) {
        args = new String[]{"__", "__"};
        
        testMeErrors x = new testMeErrors(args[0], args[1]);
        
        System.out.println("Main Tests:");
        for (int i=0; i<100; i++)
            x.test();
        
    }
}
