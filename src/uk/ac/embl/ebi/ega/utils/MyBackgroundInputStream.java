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

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 *
 * @author asenf
 */

public class MyBackgroundInputStream extends InputStream {
        private static final int QUEUE_SIZE = 5;
        private static final int BUFFER_SIZE = 32768;
        private static final byte[] EOF_MARKER = new byte[0];

        // These variables are accessed from both threads
        private final BlockingQueue<byte[]> inQueue;
        private final BlockingQueue<byte[]> recycleQueue;
        private final int bufferSize;
        private final InputStream sourceStream;
        private volatile boolean closed;

        // These variables are only accessed from the reader thread
        private byte[] currentBuffer;
        private int currentIndex;
        private Thread loaderThread;

        public MyBackgroundInputStream(InputStream source) {
                this(source, QUEUE_SIZE, BUFFER_SIZE);
        }

        public MyBackgroundInputStream(InputStream source, int queueSize, int bufferSize)
        {
                inQueue = new ArrayBlockingQueue<byte[]>(queueSize);
                recycleQueue = new ArrayBlockingQueue<byte[]>(queueSize + 1);
                sourceStream = source;
                this.bufferSize = bufferSize;
        }

        @Override
        public int read() throws IOException {
                if (!ensureBuffer()) {
                        return -1;
                }
                int b = currentBuffer[currentIndex++];
                b = (b < 0)?(256 + b):b;
                recycle();
                return b;
        }

        @Override
        public int read(byte[] b) throws IOException {
                return read(b, 0, b.length);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
                int count = 0;
                while (len > 0) {
                        if (!ensureBuffer()) {
                                return count == 0 ? -1 : count;
                        }
                        int remaining = currentBuffer.length - currentIndex;
                        int bytesToCopy = Math.min(remaining, len);
                        System.arraycopy(currentBuffer, currentIndex, b, off, bytesToCopy);
                        count += bytesToCopy;
                        currentIndex += bytesToCopy;
                        off += bytesToCopy;
                        len -= bytesToCopy;
                        recycle();
                }
                return count;
        }

        private boolean ensureBuffer() throws IOException {
                if (loaderThread == null) {
                        loaderThread = new Thread(new Loader(), "BackgroundInputStream");
                        loaderThread.start();
                }
                if (currentBuffer == null) {
                        try {
                                currentBuffer = inQueue.take();
                        } catch (InterruptedException e) {
                                throw new IOException("Failed to take a buffer from the queue", e);
                        }
                        currentIndex = 0;
                }
                return currentBuffer != EOF_MARKER;
        }

        private void recycle() {
                if (currentIndex == currentBuffer.length) {
                        if (currentIndex == bufferSize) {
                                recycleQueue.offer(currentBuffer);
                        }
                        currentBuffer = null;
                }
        }

        @Override
        public int available() throws IOException {
                return currentBuffer == null ? 0 : currentBuffer.length;
        }

        @Override
        public void close() throws IOException {
                closed = true;
                inQueue.clear();
                recycleQueue.clear();
                currentBuffer = null;
        }

        private class Loader implements Runnable {
                @Override
                public void run() {
                        {
                                int bytesRead = 0;
                                while (!closed) {
                                        byte[] buffer = recycleQueue.poll();
                                        if (buffer == null) {
                                                buffer = new byte[bufferSize];
                                        }
                                        int offset = 0;
                                        try {
                                                while ((offset < bufferSize) && ((bytesRead = sourceStream.read(buffer, offset, bufferSize - offset)) != -1)) {
                                                        offset += bytesRead;
                                                }
                                        } catch (IOException e) {
                                                throw new RuntimeException("Unable to read from stream", e);
                                        }
                                        if (offset < bufferSize) {
                                                buffer = Arrays.copyOf(buffer, offset);
                                        }
                                        try {
                                                inQueue.put(buffer);
                                                if (bytesRead == -1) {
                                                        inQueue.put(EOF_MARKER);
                                                        closed = true;
                                                }
                                        } catch (InterruptedException e) {
                                                throw new RuntimeException("Unable to put data onto queue", e);
                                        }
                                        if (closed) {
                                                try {
                                                        sourceStream.close();
                                                } catch (IOException e) {
                                                        throw new RuntimeException("Unable to close source stream", e);
                                                }
                                        }
                                }
                        }
                }
        }
}
 