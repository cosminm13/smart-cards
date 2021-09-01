/** 
 * Copyright (c) 1998, 2019, Oracle and/or its affiliates. All rights reserved.
 * 
 */

/*
 */

/*
 * @(#)Wallet.java	1.11 06/01/03
 */

package com.oracle.jcclassic.samples.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class Wallet extends Applet {

    /* constants declaration */

    // code of CLA byte in the command APDU header
    final static byte Wallet_CLA = (byte) 0x80;

    // codes of INS byte in the command APDU header
    final static byte VERIFY = (byte) 0x20;
    final static byte CREDIT = (byte) 0x30;
    final static byte DEBIT = (byte) 0x40;
    final static byte GET_BALANCE = (byte) 0x50;
    
    final static byte UPDATE_PIN = (byte) 0x70;

    // maximum balance
    // modific balanta maxima
    final static short MAX_BALANCE = 0x1388;
    // maximum transaction amount
    // modific tranzactia maxima
    final static short MAX_TRANSACTION_AMOUNT = 500;

    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    // signal invalid transaction amount
    // amount > MAX_TRANSACTION_AMOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    // signal the the balance becomes negative
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    
    final static short SW_SECURITY_STATUS_NOT_SATISFIED = 0x6A86;

    /* instance variables declaration */
    OwnerPIN pin;
    short balance;
    
    // punctele de loialitate
    short loyalty;
    
    // id-ul magazinului de la care se face debitarea
    byte shopID;
    
    // optiunea de plata a clientului
    byte paymentMethod;

    private Wallet(byte[] bArray, short bOffset, byte bLength) {

        // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        // The installation parameters contain the PIN
        // initialization value
        pin.update(bArray, (short) (bOffset + 1), aLen);
        register();

    } // end of the constructor

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a Wallet applet instance
        new Wallet(bArray, bOffset, bLength);
    } // end of install method

    @Override
    public boolean select() {

        // The applet declines to be selected
        // if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }

        return true;

    }// end of select method

    @Override
    public void deselect() {

        // reset the pin value
        pin.reset();

    }

    @Override
    public void process(APDU apdu) {

        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD

        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer

        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // verify the reset of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE:
                getBalance(apdu);
                return;
            case DEBIT:
                debit(apdu);
                return;
            case CREDIT:
                credit(apdu);
                return;
            case VERIFY:
                verify(apdu);
                return;
            case UPDATE_PIN:
            	updatePin(apdu);
            	return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    } // end of process method

    private void credit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        // Lc byte denotes the number of bytes in the
        // data field of the command APDU
        byte numBytes = buffer[ISO7816.OFFSET_LC];

        // indicate that this APDU has incoming data
        // and receive data starting from the offset
        // ISO7816.OFFSET_CDATA following the 5 header
        // bytes.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // it is an error if the number of data bytes
        // read does not match the number in Lc byte
        if ((numBytes != 2) || (byteRead != 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // get the credit amount
        short creditAmount = (short) ((buffer[ISO7816.OFFSET_CDATA] << 8) | buffer[ISO7816.OFFSET_CDATA+1]);
        
        // check the credit amount
        if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        if ((short) (balance + creditAmount) > MAX_BALANCE) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
        }
        
        // credit the amount
        balance = (short) (balance + creditAmount);
        

    } // end of deposit method

    private void debit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        byte numBytes = (buffer[ISO7816.OFFSET_LC]);

        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // modific numBytes 
        if ((numBytes != 4) || (byteRead != 4)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // get debit amount
        // citesc 2 bytes
        short debitAmount = (short) ((buffer[ISO7816.OFFSET_CDATA] << 8) | buffer[ISO7816.OFFSET_CDATA+1]);

        shopID = buffer[ISO7816.OFFSET_CDATA+2];
        
        paymentMethod = buffer[ISO7816.OFFSET_CDATA+3];
        
        // check debit amount
        if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        if ((short) (balance + loyalty - debitAmount) < (short) 0) {
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        }
        
        if (shopID == 0x01 || shopID == 0x02 || shopID == 0x03) {
        	loyalty += (debitAmount / 20) * 3;
        }
        else loyalty += (debitAmount / 20);
        
        // metoda de plata: 01 - doar credit, 02 - doar puncte, 03 - credit si puncte (prima data credit)
        if (paymentMethod == 0x01) {
        	if (balance - debitAmount < 0) {
        		ISOException.throwIt(SW_NEGATIVE_BALANCE);
        	}
        	else {
            	balance -= debitAmount;
        	}
        }
        else if (paymentMethod == 0x02) {
        	if (loyalty - debitAmount < 0) {
        		ISOException.throwIt(SW_NEGATIVE_BALANCE);
        	}
        	else {
        	loyalty -= debitAmount;
        	}
        }
        else if (paymentMethod == 0x03) {
          balance = (short) (balance - debitAmount);
          // daca balanta devine negativa dupa debitare, scad din loyalty si fac balanta=0
          if (balance < 0) {
          	loyalty += balance;
          	balance = 0;
          }
        }


    } // end of debit method

    private void getBalance(APDU apdu) {

        byte[] buffer = apdu.getBuffer();

        // inform system that the applet has finished
        // processing the command and the system should
        // now prepare to construct a response APDU
        // which contains data field
        short le = apdu.setOutgoing();

        if (le < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // informs the CAD the actual number of bytes
        // returned
        apdu.setOutgoingLength((byte) 2);

        // in functie de byte-ul dat in comanda, afisez balanta sau punctele de loialitate
        if (buffer[ISO7816.OFFSET_CDATA - 2] == 0x00) {
        	buffer[0] = (byte) (balance >> 8);
            buffer[1] = (byte) (balance & 0xFF);
        }
        else {
        	buffer[0] = (byte) (loyalty >> 8);
            buffer[1] = (byte) (loyalty & 0xFF);
        }
        

        // send the 2-byte balance at the offset
        // 0 in the apdu buffer
        apdu.sendBytes((short) 0, (short) 2);

    } // end of getBalance method

    private void verify(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }

    } // end of validate method
    
    private void updatePin(APDU apdu) {
    	
    	byte[] buffer = apdu.getBuffer();
    	
    	// extrag din buffer lungimea noului pin si cea a vechiului pin
    	byte newPinLength = buffer[ISO7816.OFFSET_LC + 0x01];
    	byte oldPinLength = buffer[(short) (ISO7816.OFFSET_CDATA + newPinLength + 0x01)];
    	
    	// verific pin-ul vechi
    	if (pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + newPinLength + 0x02), oldPinLength) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    	
    	// verific lungimea pin-ului nou
    	if (newPinLength < 0x02 || newPinLength > MAX_PIN_SIZE) {
    		ISOException.throwIt(SW_VERIFICATION_FAILED);
    	}
    	
    	// fac update
    	if (select() == true) {
    		pin.update(buffer, (short)(ISO7816.OFFSET_LC + 0x01), newPinLength);
    	}
    	else {
    		ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
    	}
    }
    
    
} // end of class Wallet

