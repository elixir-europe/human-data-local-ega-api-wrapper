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

import io.netty.channel.ChannelHandlerContext;
import java.util.TimerTask;
import uk.ac.embl.ebi.ega.egaapiwrapper.EgaSimpleNettyHandler;

/**
 *
 * @author asenf
 */
public class MyTimerTask extends TimerTask {

    private EgaSimpleNettyHandler api;
    private ChannelHandlerContext ctx;
    private int countDown = 0;
    
    public MyTimerTask(int countDown, EgaSimpleNettyHandler api, ChannelHandlerContext ctx) {
        this.countDown = countDown;
        this.api = api;
        this.ctx = ctx;
    }
            
    @Override
    public void run() {
        // Update DB
        System.out.println("TimerTask: " + this.countDown);
        this.countDown--;
        if (this.countDown <= 0) {
            this.api.cancelMe(this.ctx);
        }
    }    
}
