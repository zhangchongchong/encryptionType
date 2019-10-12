//
//  SecretViewController.h
//  加密方式汇总
//
//  Created by 张冲 on 2019/8/26.
//  Copyright © 2019 张冲. All rights reserved.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN
typedef enum : NSUInteger {
    Base64Type,
    MD5Type,
    AESType,
    RSAType
} SecretType;
@interface SecretViewController : UIViewController
@property (nonatomic,assign) SecretType secretType;
- (IBAction)secretClick:(UIButton *)sender;
@property (weak, nonatomic) IBOutlet UITextField *decodeText;
- (IBAction)decodeClick:(UIButton *)sender;
@property (weak, nonatomic) IBOutlet UILabel *showLabel;
@property (weak, nonatomic) IBOutlet UITextField *secretTextField;
@end

NS_ASSUME_NONNULL_END
