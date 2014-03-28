/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.cipher;

import java.io.IOException;

/**
 * Base exception class for all cipher operations
 */
public class NativeAESCipherException extends IOException {
  /**
	 * 
	 */
	private static final long serialVersionUID = 7051560311140888025L;

public NativeAESCipherException(String message) {
    super(message);
  }
}
