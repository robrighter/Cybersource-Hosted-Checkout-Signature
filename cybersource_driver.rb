require 'rubygems'
require 'hmac-sha1'
require 'digest/sha1'
require 'base64'

class CyberSourceDriver
  PUBLIC_KEY = "PUT YOUR PUBLIC KEY HERE"
  PRIVATE_KEY = "PUT YOUR PRIVATE KEY HERE"
  MERCHANT_ID = "PUT YOUR MERCHANT ID HERE"
  SERIAL_NUMBER = "PUT YOUR SERIAL NUMBER HERE"
  
  def hopHash(data, key)
    myhmac = HMAC::SHA1.new(key.toutf8)
    myhmac.update(data.toutf8)
    Base64.encode64(myhmac.digest).chomp
  end
  
  def getMicrotime()
    ((Time.now - Time.gm(1970,1,1)) *1000).to_i.to_s
  end
  
  def insertSignature(amount, currency)
    timestamp = getMicrotime()
    data = MERCHANT_ID + amount + currency + timestamp
    pub_digest = hopHash(data, PUBLIC_KEY)
    "<input type='hidden' name='amount' value='#{amount}' >\n" + 
    "<input type='hidden' name='currency' value='#{currency}' >\n" + 
    "<input type='hidden' name='orderPage_timestamp' value='#{timestamp}' >\n" + 
    "<input type='hidden' name='merchantID' value='#{MERCHANT_ID}' >\n" + 
    "<input type='hidden' name='orderPage_signaturePublic' value='#{pub_digest}' >\n" +
    "<input type='hidden' name='orderPage_version' value='4' >\n" + 
    "<input type='hidden' name='orderPage_serialNumber' value='#{SERIAL_NUMBER}' >\n"
  end
  
  def insertSignature3(amount, currency, orderPage_transactionType)
    timestamp = getMicrotime()
    data = MERCHANT_ID + amount + currency + timestamp + orderPage_transactionType
    pub_digest = hopHash(data, PUBLIC_KEY)

    "<input type='hidden' name='orderPage_transactionType' value='#{orderPage_transactionType}' >\n" +
    "<input type='hidden' name='amount' value='#{amount}' >\n" + 
    "<input type='hidden' name='currency' value='#{currency}' >\n" + 
    "<input type='hidden' name='orderPage_timestamp' value='#{timestamp}' >\n" + 
    "<input type='hidden' name='merchantID' value='#{MERCHANT_ID}' >\n" + 
    "<input type='hidden' name='orderPage_signaturePublic' value='#{pub_digest}' >\n" +
    "<input type='hidden' name='orderPage_version' value='4' >\n" + 
    "<input type='hidden' name='orderPage_serialNumber' value='#{SERIAL_NUMBER}' >\n"
  end
  
  def insertSubscriptionSignature(subscriptionAmount,subscriptionStartDate,subscriptionFrequency,subscriptionNumberOfPayments,subscriptionAutomaticRenew)
    data = subscriptionAmount + subscriptionStartDate + subscriptionFrequency + subscriptionNumberOfPayments + subscriptionAutomaticRenew
    pub_digest = hopHash(data, PUBLIC_KEY)
    "<input type='hidden' name='recurringSubscriptionInfo_amount' value='#{subscriptionAmount}' >\n" + 
    "<input type='hidden' name='recurringSubscriptionInfo_numberOfPayments' value='#{subscriptionNumberOfPayments}' >\n" + 
    "<input type='hidden' name='recurringSubscriptionInfo_frequency' value='#{subscriptionFrequency}' >\n" + 
    "<input type='hidden' name='recurringSubscriptionInfo_automaticRenew' value='#{subscriptionAutomaticRenew}' >\n" + 
    "<input type='hidden' name='recurringSubscriptionInfo_startDate' value='#{subscriptionStartDate}' >\n" + 
    "<input type='hidden' name='recurringSubscriptionInfo_signaturePublic' value='#{pub_digest}' >\n" 
  end
  
  def insertSubscriptionIDSignature(subscriptionID)
    pub_digest = hopHash(subscriptionID, PUBLIC_KEY)
    "<input type='hidden' name='paySubscriptionCreateReply_subscriptionID' value='#{subscriptionID}' >\n" + 
    "<input type='hidden' name='paySubscriptionCreateReply_subscriptionIDPublicSignature' value='#{pub_digest}' >\n"
  end
  
  def verifySignature(data, signature)
      ((hopHash(data, PUBLIC_KEY).to_s == signature.to_s))
  end
  
  def verifyTransactionSignature(message)
       fields = message['signedFields'].split(',')
       data = '';
       fields.each { |field| data << message[field] }
       (verifySignature(data, message['transactionSignature']))
  end
  
end