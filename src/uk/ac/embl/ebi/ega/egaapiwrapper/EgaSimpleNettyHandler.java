/*
 * Copyright 2012 The Netty Project
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

package uk.ac.embl.ebi.ega.egaapiwrapper;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.DefaultChannelPromise;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderUtil;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.LastHttpContent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;
import uk.ac.embl.ebi.ega.utils.MyResultObject;
import uk.ac.embl.ebi.ega.utils.MyTimerTask;
import uk.ac.embl.ebi.ega.utils.RestyTimeOutOption;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONObject;
import us.monoid.web.AbstractContent;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;
import static us.monoid.web.Resty.data;
import static us.monoid.web.Resty.form;

public class EgaSimpleNettyHandler extends SimpleChannelInboundHandler<HttpObject> {

    private final HttpRequest r;
    private final String f;
    private final String dest_path;
    private String down_path;
    private final String ticket;
    private final String org;
    
    private boolean chunked = false;
    private FileChannel f_out = null;
    
    // MD5 and Counting streams
    private MessageDigest md;
    private boolean verbose = false;

    //
    private int in_g = 0; int step = 0;
    private long read = 0, read_last = 0; 
    private long time = 0, t = 0;

    private String[] result;
    private MyResultObject mro;
    
    private String HOST;
    private int PORT;
    
    private File f_, ff_;
    
    private Timer theTimer = null;
    
    // Information passed in from the main function: request and filename - Establish File path & name
    public EgaSimpleNettyHandler(HttpRequest r, String down_name, String dest_path, String ticket, MyResultObject mro, String HOST, int PORT, String org) {
        super(true); // false  (AutoRelease)
        this.r = r;
        this.f = down_name;
        this.dest_path = dest_path;

        // Setting up Output File
        File out = null;
        this.down_path = null;
        try {
            if (down_name != null && !down_name.equalsIgnoreCase("null")) { // A file is specified
                String down_path = down_name;
                if (this.dest_path!= null && this.dest_path.length() > 0)
                    down_path = this.dest_path + down_name;
                if (down_path!=null) {
                    out = new File(down_path);
                    if (out.getParentFile()!=null)
                        out.getParentFile().mkdirs();
                    out.createNewFile();
                }

                if (out!=null && out.exists()) {// File created successfully
                    this.down_path = out.getAbsolutePath();
                    if (verbose) System.out.println("File Stream established for " + down_path + " (" + ticket + ")");
                } else { // Error creating file - use ticket as file name in local dir
                    String backupPath = ticket + ( (org==null||org.length()==0)?".cip":".gpg" );
                    out = new File(backupPath);
                    if (out!=null) out.createNewFile();
                    
                    if (out.exists() && verbose) {
                        this.down_path = out.getAbsolutePath();
                        System.out.println("File " + down_path + " could not be created. Using " + out.getAbsolutePath() + " instead.");
                    }
                    if ((out == null || !out.exists()) && verbose) System.out.println("Stream downloaded, but NOT SAVED! ERROR CONDITION!");
                }
                
            } else { // download to Null
                // Nothing to do
                if (verbose) System.out.println("Download to NULL");
            }
        } catch (Throwable th) {
            System.err.println(th.toString());
        }
        
        this.ticket = ticket;
        this.org = org;
        this.mro = mro;
        this.HOST = HOST;
        this.PORT = PORT;
        try {
            this.md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println(ex.toString());
        }
        if (verbose) System.out.println("Handler for ticket " + this.ticket + " set up! (Saving to: " + this.down_path + ")");
    }

    // Upon connection setup, send the prepared HTTP request
    @Override
    public void channelActive(final ChannelHandlerContext ctx) {        
        // Establish Output File before request has been sent (if a filename was specified)
        if (this.down_path != null && this.down_path.length() > 0) {
            try {
                FileOutputStream fos = new FileOutputStream(this.down_path + ".egastream");
                f_ = new File(this.down_path + ".egastream");
                ff_ = new File(this.down_path);
                this.f_out = fos.getChannel();
            } catch (FileNotFoundException ex) {
                System.out.println("Error creating local file for " + this.down_path);
                Logger.getLogger(EgaSimpleNettyHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
            if (verbose) System.out.println("File channel established for " + this.down_path);
        } else {
            System.out.println("No File is specified, so nothing is saved for ticket " + this.ticket);
        }
        
        ctx.writeAndFlush(r);
        
        TimerTask timerTask = new MyTimerTask(5, this, ctx);
        theTimer = new Timer(true);
        theTimer.scheduleAtFixedRate(timerTask, 60000, 60000); // immediately, then every 30 min
        if (verbose) System.out.println("Timer started!");        
        
        this.read = 0;
        this.time = System.currentTimeMillis();
        this.t = System.currentTimeMillis();        
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        // Visual Only code - progress reports
        if (this.verbose && (read/104857600L > step)) {
            step++;
            long delta = read-read_last;
            read_last = read;
            long timedelta = System.currentTimeMillis() - time;
            time = System.currentTimeMillis();
            double mbs = ( (delta*1.0)/1024.0/1024.0 ) / ( (timedelta*1.0) / 1000 );
            System.out.println("Netty Read: " + read + "   ticket: " + ticket + "  " + mbs + " MB/s");
        }
        if (System.currentTimeMillis()-t>5000) { // && verbose) {
            //System.out.println("ticket " + this.ticket + " xferred: " + read);
            System.out.println("file " + f + " xferred: " + read);
            t = System.currentTimeMillis();
        }
    }

    @Override
    public void exceptionCaught(final ChannelHandlerContext ctx, final Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }

    // Received data/response from the server
    @Override
    protected void messageReceived(ChannelHandlerContext chc, HttpObject msg) throws Exception {
        if (this.theTimer != null) {
            this.theTimer.cancel();
            this.theTimer = null;
            if (verbose) System.out.println("Timer cancelled!");
        }
        
        if (msg instanceof HttpResponse) { // Read the Header
            HttpResponse response = (HttpResponse) msg;
            
            if (HttpHeaderUtil.isTransferEncodingChunked(response)) {
                chunked = true;
            } else {
                chunked = false;
            }
        }

        if (msg instanceof HttpContent) {
            HttpContent content = (HttpContent) msg;

            if (chunked) { // Data Stream
                this.md.update(content.content().nioBuffer());
                this.read += content.content().readableBytes();
                if (this.f_out!=null) this.f_out.write(content.content().nioBuffer());                              
            } else {
                System.out.println("Reply: " + content.toString());
            }
            
            if (content instanceof LastHttpContent) { // Last bit of download data (run only once!)
                if (verbose) System.out.println("Last Content Received");
                chc.close(); // -- otherwise I get an error
                if (this.f_out!=null) this.f_out.close();
                
                // End-of-download code: avg speed and MD5 verification
                try {
                    String dataServer = HOST+":"+PORT;
                    byte[] digest = md.digest();
                    BigInteger bigInt = new BigInteger(1,digest);
                    String hashtext = bigInt.toString(16);
                    while(hashtext.length() < 32 )
                        hashtext = "0"+hashtext;
                    result = new String[]{String.valueOf(read)};

                    if (verbose) System.out.println("Getting Server MD5 for " + ticket);
                    JSONResource json = null;
                    final String url_ = "http://" + dataServer + "/ega/rest/download/v2/results/" +
                            (ticket.contains("?")?ticket.substring(0, ticket.indexOf("?")-1):ticket) + "?md5="+hashtext;
                    
                    Resty r = new Resty(new RestyTimeOutOption(4000, 4000));
                    json = restCall(r, url_, null, null);
                    
                    if (json!=null) {
                        try {
                            JSONObject jobj = (JSONObject) json.get("response");
                            JSONArray jsonarr = (JSONArray)jobj.get("result");
                            if (verbose) System.out.println("Received Server MD5 for " + ticket + "  " + jsonarr);
                            // Basic check..
                            if (read > 0 && read == Long.parseLong(jsonarr.getString(1))) {
                                if (verbose) System.out.println("Success! " + ticket);
                                this.mro.size = read;
                                this.mro.success = true;
                                if (ff_!=null && ff_.exists()) ff_.delete();
                                if (ff_!=null && f_!=null) f_.renameTo(ff_); // Switch from "file.egastream" to just "file"
                            } else {
                                if (verbose) System.out.println("Failed " + ticket + ". Waiting, and re-try.");
                                Thread.sleep(1500);
                            }
                        } catch (Throwable t) {
                            System.out.println("Couldn't get MD5 for (2) " + ticket);
                            this.mro.skip_md5 = true;
                            if (f_!=null && f_.exists()) f_.delete();
                            if (ff_!=null && ff_.exists()) ff_.delete();
                        }
                    } else {
                        System.out.println("Couldn't get MD5 for (1) " + ticket);
                        this.mro.skip_md5 = true;
                        if (f_!=null && f_.exists()) f_.delete();
                        if (ff_!=null && ff_.exists()) ff_.delete();
                    }
                } catch (Exception ex) {
                    System.out.println("Final Error: " + ((ex!=null)?ex.getLocalizedMessage():"null"));
                    if (f_!=null && f_.exists()) f_.delete();
                    if (ff_!=null && ff_.exists()) ff_.delete();
                }
            }
        }
    }
    
    public void cancelMe(ChannelHandlerContext ctx) {
        if (verbose) System.out.println("Cancelling!!");
        try {
            this.close(ctx, new DefaultChannelPromise(ctx.channel()));
        } catch (Exception ex) {
            Logger.getLogger(EgaSimpleNettyHandler.class.getName()).log(Level.SEVERE, null, ex);
            System.err.println(ex.toString());
        }
        this.theTimer.cancel();
        this.theTimer = null;
    }

    private JSONResource restCall(Resty r, String url, AbstractContent dat, String formname) {
        JSONResource json = null;
        
        boolean errorCondition = true;
        int countdown = 10;
 
        // Retry REST calls up to 10 times before giving up
        while (errorCondition && countdown-- > 0) {
            try {
                // Call - depending on what data is supplied
                if (dat==null) {
                    json = r.json(url);
                } else if (dat!=null && formname == null) {
                    // Submit without form name
                } else if (dat!=null && formname!=null && formname.length()>0) {
                    json = r.json(url, form( data("loginrequest", dat) )); // Uses Timout Class
                }
                errorCondition = false;
            } catch (IOException ex) {
                Logger.getLogger(EgaAPIWrapper.class.getName()).log(Level.SEVERE, null, ex);
                System.err.println(ex.toString());
            }
            
            // test that there is a result
            if (json == null) {
                errorCondition = true;
            } else {
                try {JSONObject jobj = (JSONObject) json.get("response");} catch (Throwable th) {
                    errorCondition = true;
                }
            }
            
            // In case of error, wait a bit, up to 4 seconds
            if (errorCondition) {
                Random x = new Random();
                long y = Math.abs(x.nextInt(4000));
                try {
                    Thread.sleep( (y>4000?4000:y) );
                } catch (InterruptedException ex) {
                    System.err.println(ex.toString());
                }
            }
        }
        
        // retrn the result object; if all else fails, return null
        return json;
    }
}
