import * as cdk from "aws-cdk-lib";
import * as cloudtrail from "aws-cdk-lib/aws-cloudtrail";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sqs from "aws-cdk-lib/aws-sqs";
import { Construct } from "constructs";

export class SqsCloudtrailStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // テスト用のSQS
    const queue = new sqs.Queue(this, "Queue", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // カスタマーマネージドキー
    const cmk = new kms.Key(this, "Cmk", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // CloudTrailのアクセス権を許可
    cmk.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal("cloudtrail.amazonaws.com")],
        actions: ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"],
        resources: ["*"],
      })
    );

    // 証憑を格納するS3
    const trailBucket = new s3.Bucket(this, "TrailBucket", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      encryptionKey: cmk,
      enforceSSL: true,
    });

    // バケットポリシーを明示的に作成
    const trailBucketPolicy = new s3.BucketPolicy(this, "TrailBucketPolicy", {
      bucket: trailBucket,
    });

    // CloudTrailのアクセス権を付与
    trailBucketPolicy.document.addStatements(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal("cloudtrail.amazonaws.com")],
        actions: ["s3:GetBucketAcl"],
        resources: [trailBucket.bucketArn],
      }),
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal("cloudtrail.amazonaws.com")],
        actions: ["s3:PutObject"],
        resources: [trailBucket.arnForObjects(`*`)],
        conditions: {
          StringEquals: {
            "s3:x-amz-acl": "bucket-owner-full-control",
          },
        },
      })
    );

    // CloudTrailのCloudwatchログ
    const logGroup = new logs.LogGroup(this, "logGroup", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Cloudwatchログのロール
    const logRole = new iam.Role(this, "logRole", {
      assumedBy: new iam.ServicePrincipal("cloudtrail.amazonaws.com"),
    });
    logGroup.grantWrite(logRole);
    trailBucket.grantWrite(logRole);
    cmk.grantEncryptDecrypt(logRole);

    // CloudTrail
    const trail = new cloudtrail.CfnTrail(this, "Trail", {
      isLogging: true,
      s3BucketName: trailBucket.bucketName,
      kmsKeyId: cmk.keyArn,
      isMultiRegionTrail: false,
      includeGlobalServiceEvents: false,
      enableLogFileValidation: true,
      cloudWatchLogsLogGroupArn: logGroup.logGroupArn,
      cloudWatchLogsRoleArn: logRole.roleArn,
      advancedEventSelectors: [
        {
          fieldSelectors: [
            { field: "eventCategory", equalTo: ["Data"] },
            { field: "resources.type", equalTo: ["AWS::SQS::Queue"] },
          ],
        },
      ],
      s3KeyPrefix: "AWS-SQS-Queue",
    });

    // 明示的に依存関係を定義
    trail.node.addDependency(trailBucketPolicy);
  }
}
