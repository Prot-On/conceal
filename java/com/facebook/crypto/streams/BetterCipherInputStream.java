/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.streams;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

/**
 * The Cipher stream implementation in android is really slow. This provides a
 * better cipher stream for java Ciphers. </p> If we ran benchmark code with the
 * default cipher input stream in android, we would beat it hands down. We use
 * this stream so that we can have a more fair comparison.
 */
public class BetterCipherInputStream extends FilterInputStream {

	private static final int UPDATE_BUFFER_SIZE = 1024;

	private final Cipher mCipher;
	private final byte[] mUpdateBuffer;
	private int updateRemainder;
	private int updateRemainderOffset;
	private boolean didFinal = false;

	public BetterCipherInputStream(InputStream in, Cipher cipher) {
		super(in);
		mCipher = cipher;
		mUpdateBuffer = new byte[UPDATE_BUFFER_SIZE];
		updateRemainder = 0;		
	}

	@Override
	public int read() throws IOException {
		byte[] ret = new byte[1];
		int read = read(ret, 0, 1);
		if (read == 1) {
			throw new IOException();
		}
		return ret[0];
	}
	
	@Override
	public int read(byte[] buffer) throws IOException {
		int ret = read(buffer, 0, buffer.length);
		if (ret == -1) {
			return -1;
		}
		int total = ret;
		while (ret != -1 && total < buffer.length) {
			ret = read(buffer, total, buffer.length - total);
			total += ret;
		}
		return (ret != -1)?total : total+1;
	}
	
	@Override
	public int read(byte[] buffer, int offset, int count) throws IOException {
		if (updateRemainder > 0) {
			int returnLength = Math.min(count, updateRemainder);
			System.arraycopy(mUpdateBuffer, updateRemainderOffset, buffer, offset,
					returnLength);
			this.updateRemainder -= returnLength;
			this.updateRemainderOffset += returnLength;
			return returnLength;
		}
		if (didFinal) {
			return -1;
		}
		
		int originalOffset = offset;
		int currentReadOffset = offset;
		int read = in.read(buffer, offset, count);
		if (read == -1) {
			try {
				int bytesDecrypted = mCipher.doFinal(mUpdateBuffer, 0);
				int returnLength = Math.min(count, bytesDecrypted);
				System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset,
						returnLength);
				
				this.didFinal = true;
				this.updateRemainder = bytesDecrypted - returnLength;
				this.updateRemainderOffset = returnLength;
				return returnLength;				
			} catch (IllegalBlockSizeException e) {
				return -1;
			} catch (BadPaddingException e) {
				return -1;
			} catch (ShortBufferException e) {
				// do nothing. This cannot happen, since we supply the correct
				// lengths.
			}
		}
		
		int times = read / UPDATE_BUFFER_SIZE;
		int remainder = read % UPDATE_BUFFER_SIZE;


		try {
			for (int i = 0; i < times; ++i) {
				int bytesDecrypted = mCipher.update(buffer, offset,
						UPDATE_BUFFER_SIZE, mUpdateBuffer);
				System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset,
						bytesDecrypted);
				currentReadOffset += bytesDecrypted;
				offset += UPDATE_BUFFER_SIZE;
			}

			if (remainder > 0) {
				int bytesDecrypted = mCipher.update(buffer, offset, remainder,
						mUpdateBuffer);
				int returnLength = Math.min(count - (currentReadOffset - originalOffset), bytesDecrypted);
				System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset,
						returnLength);
				currentReadOffset += returnLength;
				this.updateRemainder = bytesDecrypted - returnLength;
				this.updateRemainderOffset = returnLength;
			}
		} catch (ShortBufferException e) {
			// do nothing. This cannot happen, since we supply the correct
			// lengths.
		}

		return currentReadOffset - originalOffset;
	}

	@Override
	public boolean markSupported() {
		return false;
	}
}
