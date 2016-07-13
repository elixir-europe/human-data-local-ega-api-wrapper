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

import uk.ac.embl.ebi.ega.egaapiwrapper.EgaAPIWrapper;

/**
 *
 * @author asenf
 */
public class testMeGlobus {
    private EgaAPIWrapper api;
    private boolean login = false;
    
    public testMeGlobus(String username, String password) {
        
        this.api = new EgaAPIWrapper("ega.ebi.ac.uk", "ega.ebi.ac.uk", false);
        
        login = this.api.globusLogin(username, password.toCharArray());
        //login = this.api.globusLogin("", "".toCharArray());
       
        System.out.println("Login Success? " + login);        
    }
    
    private void test() {
        if (!login) return;
        System.out.println("Commencing Tests");

        // Test 1: Initiate Transfer (that's really the only function there is...)
        String request = "testGlob"; // request to be transferred
        String endpoint = "asenf#laptop-test"; // destination endpoint
        String uid = this.api.globusStartTransfer(request, endpoint);
        
        System.out.println("UID = " + uid);
    }

    public static void main(String[] args) {

        //testMeGlobus x = new testMeGlobus(args[0], args[1]);
        testMeGlobus x = new testMeGlobus("__", "__");

        x.test();
        
    }
}
