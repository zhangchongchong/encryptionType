//
//  ViewController.h
//  加密方式汇总
//
//  Created by 张冲 on 2019/8/26.
//  Copyright © 2019 张冲. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController
- (IBAction)base64Click:(UIButton *)sender;
- (IBAction)MD5Click:(UIButton *)sender;
@property (weak, nonatomic) IBOutlet UIButton *AESClick;
- (IBAction)AESClick:(UIButton *)sender;
- (IBAction)RSAClick:(UIButton *)sender;

@end

