//
//  SecretViewController.m
//  加密方式汇总
//
//  Created by 张冲 on 2019/8/26.
//  Copyright © 2019 张冲. All rights reserved.
//

#import "SecretViewController.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
@interface SecretViewController ()

@end

@implementation SecretViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSLog(@"密码页");
    if (self.secretType == Base64Type) {
        self.title = @"Base 64";
    }else if (self.secretType == MD5Type){
        self.title = @"MD5";
    }else if (self.secretType == AESType){
        self.title = @"AES";
    }else if (self.secretType == RSAType){
        self.title = @"RSA";
    }
    // Do any additional setup after loading the view.
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/
//加密
- (IBAction)secretClick:(UIButton *)sender {
    NSString *string = self.secretTextField.text;
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSString *encodeString ;
    if (self.secretType == Base64Type) {
        encodeString = [self base64EncodedStringWithData:data];
    }else if (self.secretType == MD5Type){
        encodeString = [self md5SignWithString:string];
    }else if (self.secretType == AESType){
        NSString *aesKey = @"a1b2c3d4e5f6g7h8";
        NSData *keyData3 = [aesKey dataUsingEncoding:NSUTF8StringEncoding];
        NSData *sourceData3 = [string dataUsingEncoding:NSUTF8StringEncoding];
        NSData *encodeData3 = [self encryptData:sourceData3 key:keyData3];
        NSLog(@"encodeData3 : %@", encodeData3);

    }else if (self.secretType == RSAType){
//        NSString *string4 = @"abcdefghijklmnopqrstuvwxyz";
//        NSString *encodeString4 = [self encryptString:string4
//                                                  publicKey:mPublicKey];
//        NSLog(@"encodeString4 : %@", encodeString4);
    }
    self.showLabel.text = encodeString;
    NSLog(@"encodeString : %@", encodeString);
}
//解密
- (IBAction)decodeClick:(UIButton *)sender {
    //使用Base64执行解密操作
    NSString *decodeString = nil;

    if (self.secretType == Base64Type) {
        NSData *decodeData = [self base64DecodeDataWithString:self.showLabel.text];
        decodeString = [[NSString alloc] initWithData:decodeData
                                             encoding:NSUTF8StringEncoding];
        NSLog(@"decodeString : %@", decodeString);
    }else if (self.secretType == MD5Type){
        decodeString = [self md5SignWithString:self.showLabel.text];
    }else if (self.secretType == AESType){
        //使用AES执行解密操作
        NSString *decodeString3 = nil;
        NSString *string  = self.showLabel.text;
        NSString *aesKey = @"a1b2c3d4e5f6g7h8";
        NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
        NSData *keyData3 = [aesKey dataUsingEncoding:NSUTF8StringEncoding];

        NSData *decodeData3 = [self decryptData:data
                                                  key:keyData3];

        decodeString = [[NSString alloc] initWithData:decodeData3
                                              encoding:NSUTF8StringEncoding];
        NSLog(@"decodeString3 : %@", decodeString3);
    }else if (self.secretType == RSAType){
//        //使用RSA执行解密操作
//        NSString *decodeString4 = [RSAEncrypt decryptString:encodeString4
//                                                 privateKey:mPrivateKey];
//        NSLog(@"decodeString4 : %@", decodeString4);
    }


    self.decodeText.text = decodeString;
}
/****************************Base64.m类实现文件内容****************************/
- (NSString *)base64EncodedStringWithData:(NSData *)data
{
    //判断是否传入需要加密数据参数
    if ((data == nil) || (data == NULL)) {
        return nil;
    } else if (![data isKindOfClass:[NSData class]]) {
        return nil;
    }

    //判断设备系统是否满足条件
    if ([[[UIDevice currentDevice] systemVersion] doubleValue] <= 6.9) {
        return nil;
    }

    //使用系统的API进行Base64加密操作
    NSDataBase64EncodingOptions options;
    options = NSDataBase64EncodingEndLineWithLineFeed;
    return [data base64EncodedStringWithOptions:options];
}

- (NSData *)base64DecodeDataWithString:(NSString *)string
{
    //判断是否传入需要加密数据参数
    if ((string == nil) || (string == NULL)) {
        return nil;
    } else if (![string isKindOfClass:[NSString class]]) {
        return nil;
    }

    //判断设备系统是否满足条件
    if ([[[UIDevice currentDevice] systemVersion] doubleValue] <= 6.9) {
        return nil;
    }

    //使用系统的API进行Base64解密操作
    NSDataBase64DecodingOptions options;
    options = NSDataBase64DecodingIgnoreUnknownCharacters;
    return [[NSData alloc] initWithBase64EncodedString:string options:options];
}
/****************************MD5.m类实现文件内容****************************/
//对字符串数据进行MD5的签名
- (NSString *)md5SignWithString:(NSString *)string
{
    const char *object = [string UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(object,(CC_LONG)strlen(object),result);
    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < 16; i ++) {
        [hash appendFormat:@"%02X", result[i]];
    }
    return [hash lowercaseString];
}

//对二进制数据进行MD5的签名
- (NSData *)md5SignWithData:(NSData *)data
{
    Byte byte[CC_MD5_DIGEST_LENGTH];    //定义一个字节数组来接收结果
    CC_MD5((const void*)([data bytes]), (CC_LONG)[data length], byte);
    return [NSData dataWithBytes:byte length:CC_MD5_DIGEST_LENGTH];
}
//AES
- (NSData *)encryptData:(NSData *)data key:(NSData *)key
{
    //判断解密的流数据是否存在
    if ((data == nil) || (data == NULL)) {
        return nil;
    } else if (![data isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([data length] <= 0) {
        return nil;
    }

    //判断解密的Key是否存在
    if ((key == nil) || (key == NULL)) {
        return nil;
    } else if (![key isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([key length] <= 0) {
        return nil;
    }

    //setup key
    NSData *result = nil;
    unsigned char cKey[kCCKeySizeAES128];
    bzero(cKey, sizeof(cKey));
    [key getBytes:cKey length:kCCKeySizeAES128];

    //setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    //do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionECBMode|kCCOptionPKCS7Padding,
                                          cKey,
                                          kCCKeySizeAES128,
                                          nil,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
    } else {
        free(buffer);
    }
    return result;
}


/**
 *  AES128 + ECB + PKCS7
 *  @param data 要解密的原始数据
 *  @param key  解密 key
 *  @return  解密后数据
 */
- (NSData *)decryptData:(NSData *)data key:(NSData *)key
{
    //判断解密的流数据是否存在
    if ((data == nil) || (data == NULL)) {
        return nil;
    } else if (![data isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([data length] <= 0) {
        return nil;
    }

    //判断解密的Key是否存在
    if ((key == nil) || (key == NULL)) {
        return nil;
    } else if (![key isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([key length] <= 0) {
        return nil;
    }

    //setup key
    NSData *result = nil;
    unsigned char cKey[kCCKeySizeAES128];
    bzero(cKey, sizeof(cKey));
    [key getBytes:cKey length:kCCKeySizeAES128];

    //setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    //do decrypt
    size_t decryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionECBMode|kCCOptionPKCS7Padding,
                                          cKey,
                                          kCCKeySizeAES128,
                                          nil,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &decryptedSize);
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:decryptedSize];
    } else {
        free(buffer);
    }
    return result;
}


#pragma mark - Class Utils Method
- (BOOL)isEmptyKeyRef:(id)object
{
    if (object == nil) {
        return YES;
    } else if (object == NULL) {
        return YES;
    } else if (object == [NSNull null]) {
        return YES;
    }
    return NO;
}


#pragma mark - Private Method
- (SecKeyRef)getPrivateKeyRefWithFilePath:(NSString *)filePath keyPassword:(NSString *)keyPassword
{
    //读取私钥证书文件的内容
    NSData *certificateData = [NSData dataWithContentsOfFile:filePath];
    if ((certificateData == nil) || (certificateData == NULL)) {
        return nil;
    } else if (![certificateData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([certificateData length] <= 0) {
        return nil;
    }

    //拼接密码参数到字典中
    NSString *passwordKey = (__bridge id)kSecImportExportPassphrase;
    NSString *passwordValue = [NSString stringWithFormat:@"%@",keyPassword];
    if ((keyPassword == nil) || (keyPassword == NULL)) {
        passwordValue = @"";
    } else if (![keyPassword isKindOfClass:[NSString class]]) {
        passwordValue = @"";
    } else if ([keyPassword length] <= 0) {
        passwordValue = @"";
    }
    NSMutableDictionary *optionInfo = [[NSMutableDictionary alloc] init];
    [optionInfo setObject:passwordValue forKey:passwordKey];

    //获取私钥对象
    SecKeyRef privateKeyRef = NULL;
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    CFDataRef pkcs12Data = (__bridge CFDataRef)certificateData;
    CFDictionaryRef options = (__bridge CFDictionaryRef)optionInfo;
    OSStatus securityStatus = SecPKCS12Import(pkcs12Data, options, &items);
    if (securityStatus == noErr && CFArrayGetCount(items) > 0)
    {
        SecIdentityRef identity;
        const void *secpkey = kSecImportItemIdentity;
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        identity = (SecIdentityRef)CFDictionaryGetValue(identityDict,secpkey);
        securityStatus = SecIdentityCopyPrivateKey(identity, &privateKeyRef);
        if (securityStatus != noErr)
        {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    return privateKeyRef;
}

- (SecKeyRef)privateKeyRefWithPrivateKey:(NSString *)privateKey
{
    //判断参数是否正确
    if ((privateKey == nil) || (privateKey == NULL)) {
        return nil;
    } else if (![privateKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([privateKey length] <= 0) {
        return nil;
    }

    //解析私钥对象内容
    NSString *pKey = [NSString stringWithFormat:@"%@",privateKey];
    NSRange sposition = [pKey rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    NSRange eposition = [pKey rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    if (sposition.location != NSNotFound && eposition.location != NSNotFound)
    {
        NSUInteger endposition = eposition.location;
        NSUInteger startposition = sposition.location + sposition.length;
        NSRange range = NSMakeRange(startposition, endposition-startposition);
        pKey = [pKey substringWithRange:range];
    }
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@" "  withString:@""];

    //This will be base64 encoded, decode it.
    NSData *keyData = [self base64DecodeDataWithString:pKey];
    keyData = [self stripPrivateKeyHeader:keyData];
    if ((keyData == nil) || (keyData == NULL)) {
        return nil;
    } else if (![keyData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([keyData length] <= 0) {
        return nil;
    }

    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PrivKey";
    const void *bytes = [tag UTF8String];
    NSData *tagData = [NSData dataWithBytes:bytes length:[tag length]];

    //Delete any old lingering key with the same tag
    NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
    [attributes setObject:(__bridge id)kSecClassKey
                   forKey:(__bridge id)kSecClass];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:tagData
                   forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)attributes);

    //Add persistent version of the key to system keychain
    [attributes setObject:keyData forKey:(__bridge id)kSecValueData];
    [attributes setObject:(__bridge id)kSecAttrKeyClassPrivate
                   forKey:(__bridge id)kSecAttrKeyClass];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnPersistentRef];

    OSStatus status = noErr;
    CFTypeRef persistKey = nil;
    status = SecItemAdd((__bridge CFDictionaryRef)attributes, &persistKey);
    if (persistKey != nil) {CFRelease(persistKey);}
    if ((status != noErr) && (status != errSecDuplicateItem))
    {
        return nil;
    }

    [attributes removeObjectForKey:(__bridge id)kSecValueData];
    [attributes removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnRef];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];

    //Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    CFDictionaryRef query = (__bridge CFDictionaryRef)attributes;
    status = SecItemCopyMatching(query, (CFTypeRef *)&keyRef);
    if (status != noErr)
    {
        return nil;
    }
    return keyRef;
}

- (NSData *)stripPrivateKeyHeader:(NSData *)d_key
{
    //Skip ASN.1 private key header
    if (d_key == nil) return nil;

    unsigned long len = [d_key length];
    if (!len) return nil;

    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int idx = 22; //magic byte at offset 22

    if (0x04 != c_key[idx++]) return nil;

    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    if (!(c_len & 0x80))
    {
        c_len = c_len & 0x7f;
    }
    else
    {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }

    //Now make a new NSData from this buffer
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

- (SecKeyRef)getPublicKeyRefWithFilePath:(NSString *)filePath
{
    //读取公钥证书文件的内容
    NSData *certificateData = [NSData dataWithContentsOfFile:filePath];
    if ((certificateData == nil) || (certificateData == NULL)) {
        return nil;
    } else if (![certificateData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([certificateData length] <= 0) {
        return nil;
    }

    //将公钥证书制作成证书对象
    CFDataRef data = (__bridge CFDataRef)certificateData;
    SecCertificateRef certificateRef = SecCertificateCreateWithData(NULL, data);

    //获取公钥对象
    SecTrustRef trust = NULL;
    SecKeyRef publicKey = NULL;
    SecPolicyRef policies = SecPolicyCreateBasicX509();
    if (![[self class] isEmptyKeyRef:(__bridge id)(certificateRef)]
        && ![[self class] isEmptyKeyRef:(__bridge id)(policies)])
    {
        OSStatus status;
        status = SecTrustCreateWithCertificates((CFTypeRef)certificateRef,
                                                policies, &trust);
        if (status == noErr)
        {
            SecTrustResultType result;
            if (SecTrustEvaluate(trust, &result) == noErr)
            {
                publicKey = SecTrustCopyPublicKey(trust);
            }
        }
    }
    if (certificateRef != NULL) CFRelease(certificateRef);
    if (policies != NULL) CFRelease(policies);
    if (trust != NULL) CFRelease(trust);
    return publicKey;
}

- (SecKeyRef)publicKeyRefWithPublicKey:(NSString *)publicKey
{
    //判断参数是否正确
    if ((publicKey == nil) || (publicKey == NULL)) {
        return nil;
    } else if (![publicKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKey length] <= 0) {
        return nil;
    }

    //解析公钥对象内容
    NSString *pKey = [NSString stringWithFormat:@"%@",publicKey];
    NSRange sposition = [pKey rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange eposition = [pKey rangeOfString:@"-----END PUBLIC KEY-----"];
    if (sposition.location != NSNotFound && eposition.location != NSNotFound)
    {
        NSUInteger startposition = eposition.location;
        NSUInteger endposition = sposition.location + sposition.length;
        NSRange range = NSMakeRange(endposition, startposition-endposition);
        pKey = [pKey substringWithRange:range];
    }
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@" "  withString:@""];

    //This will be base64 encoded, decode it.
    NSData *keyData = [[self class] base64DecodeDataWithString:pKey];
    keyData = [self stripPublicKeyHeader:keyData];
    if ((keyData == nil) || (keyData == NULL)) {
        return nil;
    } else if (![keyData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([keyData length] <= 0) {
        return nil;
    }

    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PubKey";
    const void *bytes = [tag UTF8String];
    NSData *tagData = [NSData dataWithBytes:bytes length:[tag length]];

    //Delete any old lingering key with the same tag
    NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
    [attributes setObject:(__bridge id)kSecClassKey
                   forKey:(__bridge id)kSecClass];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:tagData
                   forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)attributes);

    //Add persistent version of the key to system keychain
    [attributes setObject:keyData
                   forKey:(__bridge id)kSecValueData];
    [attributes setObject:(__bridge id)kSecAttrKeyClassPublic
                   forKey:(__bridge id)kSecAttrKeyClass];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnPersistentRef];

    OSStatus status = noErr;
    CFTypeRef persistKey = nil;
    status = SecItemAdd((__bridge CFDictionaryRef)attributes, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    if ((status != noErr) && (status != errSecDuplicateItem))
    {
        return nil;
    }
    [attributes removeObjectForKey:(__bridge id)kSecValueData];
    [attributes removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnRef];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];

    //Now fetch the SecKeyRef version of the key
    SecKeyRef publicKeyRef = nil;
    CFDictionaryRef query = (__bridge CFDictionaryRef)attributes;
    status = SecItemCopyMatching(query, (CFTypeRef *)&publicKeyRef);
    if (status != noErr)
    {
        return nil;
    }
    return publicKeyRef;
}

- (NSData *)stripPublicKeyHeader:(NSData *)d_key
{
    //Skip ASN.1 public key header
    if (d_key == nil) {return nil;}

    unsigned long len = [d_key length];
    if (!len) return(nil);

    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int idx = 0;
    if (c_key[idx++] != 0x30) {return nil;}
    if (c_key[idx] > 0x80)
    {
        idx += c_key[idx] - 0x80 + 1;
    }
    else
    {
        idx++;
    }

    //PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] = {0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x01, 0x05, 0x00};
    if (memcmp(&c_key[idx], seqiod, 15)) {return nil;}
    idx += 15;
    if (c_key[idx++] != 0x03) {return nil;}
    if (c_key[idx] > 0x80)
    {
        idx += c_key[idx] - 0x80 + 1;
    }
    else
    {
        idx ++;
    }
    if (c_key[idx++] != '\0') {return nil;}

    //Now make a new NSData from this buffer
    return ([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

- (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;

    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;

    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size)
    {
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }

        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(keyRef, kSecPaddingPKCS1,
                               srcbuf + idx, data_len,
                               outbuf, &outlen);
        if (status != 0)
        {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }
        else
        {
            [ret appendBytes:outbuf length:outlen];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

- (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;

    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;

    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size)
    {
        size_t data_len = srclen - idx;
        if(data_len > src_block_size)
        {
            data_len = src_block_size;
        }

        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef, kSecPaddingNone,
                               srcbuf + idx, data_len,
                               outbuf, &outlen);
        if (status != 0)
        {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }
        else
        {
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for (int i = 0; i < outlen; i ++)
            {
                if (outbuf[i] == 0)
                {
                    if (idxFirstZero < 0)
                    {
                        idxFirstZero = i;
                    }
                    else
                    {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            NSUInteger length = idxNextZero-idxFirstZero-1;
            [ret appendBytes:&outbuf[idxFirstZero+1] length:length];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}


#pragma mark - RSA Key File Encrypt/Decrypt Public Method
- (NSString *)encryptString:(NSString *)originString publicKeyPath:(NSString *)publicKeyPath
{
    //判断originString参数是否正确
    if ((originString == nil) || (originString == NULL)) {
        return nil;
    } else if (![originString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([originString length] <= 0) {
        return nil;
    }

    //判断publicKeyPath参数是否正确
    if ((publicKeyPath == nil) || (publicKeyPath == NULL)) {
        return nil;
    } else if (![publicKeyPath isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKeyPath length] <= 0) {
        return nil;
    }

    //获取公钥对象和需要加密的字符串内容编码数据流
    SecKeyRef publicKeyRef = [self getPublicKeyRefWithFilePath:publicKeyPath];
    NSData *originData = [originString dataUsingEncoding:NSUTF8StringEncoding];
    if ([[self class] isEmptyKeyRef:(__bridge id)(publicKeyRef)]) {
        return nil;
    }
    if ((originData == nil) || (originData == NULL)) {
        return nil;
    } else if (![originData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([originData length] <= 0) {
        return nil;
    }

    //加密源字符串内容编码数据流的数据
    NSData *resultData = nil;
    resultData = [self encryptData:originData withKeyRef:publicKeyRef];
    return [[self class] base64EncodedStringWithData:resultData];
}

- (NSString *)decryptString:(NSString *)encryptString privateKeyPath:(NSString *)privateKeyPath privateKeyPwd:(NSString *)privateKeyPwd
{
    //判断encryptString参数是否正确
    if ((encryptString == nil) || (encryptString == NULL)) {
        return nil;
    } else if (![encryptString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([encryptString length] <= 0) {
        return nil;
    }

    //判断publicKeyPath参数是否正确
    if ((privateKeyPath == nil) || (privateKeyPath == NULL)) {
        return nil;
    } else if (![privateKeyPath isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([privateKeyPath length] <= 0) {
        return nil;
    }

    //判断密码是否存在
    NSString *keyPassword = [NSString stringWithFormat:@"%@",privateKeyPwd];
    if ((privateKeyPwd == nil) || (privateKeyPwd == NULL)) {
        keyPassword = @"";
    } else if (![privateKeyPwd isKindOfClass:[NSString class]]) {
        keyPassword = @"";
    } else if ([privateKeyPwd length] <= 0) {
        keyPassword = @"";
    }

    //获取私钥对象和需要加密的字符串内容编码数据流
    NSData *encryptData = nil, *decryptData = nil;
    SecKeyRef privateKeyRef = [self getPrivateKeyRefWithFilePath:privateKeyPath
                                                     keyPassword:privateKeyPwd];
    encryptData = [[self class] base64DecodeDataWithString:encryptString];
    if ([[self class] isEmptyKeyRef:(__bridge id)(privateKeyRef)]) {
        return nil;
    }
    if ((encryptData == nil) || (encryptData == NULL)) {
        return nil;
    } else if (![encryptData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([encryptData length] <= 0) {
        return nil;
    }
    NSStringEncoding encoding = NSUTF8StringEncoding;
    decryptData = [self decryptData:encryptData withKeyRef:privateKeyRef];
    return [[NSString alloc] initWithData:decryptData encoding:encoding];
}


#pragma mark - RSA Key String Encrypt/Decrypt Public Method
- (NSData *)encryptData:(NSData *)originData publicKey:(NSString *)publicKey
{
    //判断originData参数是否正确
    if ((originData == nil) || (originData == NULL)) {
        return nil;
    } else if (![originData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([originData length] <= 0) {
        return nil;
    }

    //判断publicKeyPath参数是否正确
    if ((publicKey == nil) || (publicKey == NULL)) {
        return nil;
    } else if (![publicKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKey length] <= 0) {
        return nil;
    }

    //获取需要加密的字符串内容编码数据流
    SecKeyRef publicKeyRef = [self publicKeyRefWithPublicKey:publicKey];
    if([[self class] isEmptyKeyRef:(__bridge id)(publicKeyRef)]){
        return nil;
    }
    return [self encryptData:originData withKeyRef:publicKeyRef];
}

- (NSString *)encryptString:(NSString *)originString publicKey:(NSString *)publicKey
{
    //判断publicKey参数是否正确
    if ((publicKey == nil) || (publicKey == NULL)) {
        return nil;
    } else if (![publicKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKey length] <= 0) {
        return nil;
    }

    //判断originString参数是否正确
    if ((originString == nil) || (originString == NULL)) {
        return nil;
    } else if (![originString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([originString length] <= 0) {
        return nil;
    }

    //获取需要加密的字符串内容编码数据流
    NSData *originData = nil, *encryptData = nil;
    SecKeyRef publicKeyRef = [self publicKeyRefWithPublicKey:publicKey];
    originData = [originString dataUsingEncoding:NSUTF8StringEncoding];
    if([[self class] isEmptyKeyRef:(__bridge id)(publicKeyRef)]){
        return nil;
    }
    if ((originData == nil) || (originData == NULL)) {
        return nil;
    } else if (![originData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([originData length] <= 0) {
        return nil;
    }
    encryptData = [self encryptData:originData withKeyRef:publicKeyRef];
    return [[self class] base64EncodedStringWithData:encryptData];
}

- (NSString *)decryptString:(NSString *)encryptString privateKey:(NSString *)privateKey
{
    //判断publicKey参数是否正确
    if ((privateKey == nil) || (privateKey == NULL)) {
        return nil;
    } else if (![privateKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([privateKey length] <= 0) {
        return nil;
    }

    //判断originString参数是否正确
    if ((encryptString == nil) || (encryptString == NULL)) {
        return nil;
    } else if (![encryptString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([encryptString length] <= 0) {
        return nil;
    }

    //获取私钥对象和需要加密的字符串内容编码数据流
    SecKeyRef privateKeyRef;
    NSData *encryptData = nil, *decryptData = nil;
    privateKeyRef = [[self class] privateKeyRefWithPrivateKey:privateKey];
    encryptData = [[self class] base64DecodeDataWithString:encryptString];
    if ([[self class] isEmptyKeyRef:(__bridge id)(privateKeyRef)]) {
        return nil;
    }
    if ((encryptData == nil) || (encryptData == NULL)) {
        return nil;
    } else if (![encryptData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([encryptData length] <= 0) {
        return nil;
    }
    NSStringEncoding encoding = NSUTF8StringEncoding;
    decryptData = [self decryptData:encryptData withKeyRef:privateKeyRef];
    return [[NSString alloc] initWithData:decryptData encoding:encoding];
}
/******************************************************************************/


@end
