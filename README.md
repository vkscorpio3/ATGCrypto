# Overview
The Payment Card Industry Data Security Standard (PCI DSS) is a set of requirements designed to enforce proper security measures that are taken by vendors to protect their customers’ credit card data and prevent credit card fraud and identify theft.  
All vendors who accept credit cards need to be compliant with all 12 groups of requirements in the PCI DSS and larger volume vendors will need to undergo PCI Compliance Audits from 3rd party security companies periodically. Failure to have an up-to-date compliance audit or failing an audit can result in fines or being unable to process credit cards, so ensuring your systems are PCI compliant is very important.

## Cardholder Data Protection in Storage
The PCI DSS requirement group number three deals with protecting cardholder data in storage. This primarily covers requirements for storing credit card numbers securely. 
Section 3.4 requires the credit card number to be encrypted using strong cryptography.  Section 3.5 requires the encryption keys to be stored securely, encrypted themselves, and restrict access to the keys. Section 3.6 covers key management including periodic key changes.  
The Spark::red PCI Compliance ATG  Encryption Module (Crypto Module) covers all three of these requirements, utilizing AES 256-bit encryption, a data encryption passphrase and a key encryption passphrase used to encrypt the data encryption passphrase. The two passphrases are stored in separate systems on separate servers. 


## Supported Features
* existing plain text data encryption;
* re-encryption of data which is currently encrypted with another non-PCI compliant system;
* re-encryption of data with a new passphrase based key (it makes the annual PCI mandated key rotation a simple matter).



ATG stores credit cards in two places by default: an order paid for with a credit card will store the credit card information with the order, and a user’s profile can have one or more saved credit cards associated with it. Unfortunately by default ATG stores these credit cards in plain text, unencrypted. This is obviously not PCI compliant. ATG’s new Commerce Reference Store (CRS) provides encryption for the user profile’s stored credit cards, but not the order’s payment credit card. The encryption is also far less secure than our module, and does not meet PCI requirements for key management and provides no ability for key rotation and re-encryption.
