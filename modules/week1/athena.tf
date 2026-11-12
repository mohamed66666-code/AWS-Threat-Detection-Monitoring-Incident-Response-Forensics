resource "aws_athena_database" "security_db" {
  name   = "security_audit_db"
  bucket = aws_s3_bucket.central_logs.id
}

resource "aws_athena_workgroup" "security_workgroup" {
  name = "security-workgroup"

  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.central_logs.id}/athena-results/"
    }
  }
}

resource "aws_athena_named_query" "create_cloudtrail_table" {
  name      = "create_cloudtrail_table"
  workgroup = aws_athena_workgroup.security_workgroup.id
  database  = aws_athena_database.security_db.name
  query     = <<EOF
CREATE EXTERNAL TABLE IF NOT EXISTS security_audit_db.cloudtrail_logs (
  version string,
  usertype string,
  usarn string,
  uaccountid string,
  usessioncontext map<string,string>,
  sourceipaddress string,
  useragent string,
  requestparameters string,
  responseelements string,
  additionaleventdata string,
  requestid string,
  eventid string,
  readonly string,
  resources array<struct<arn:string,accountid:string,type:string,resourcename:string>>,
  eventtype string,
  apiversion string,
  recipientaccountid string,
  serviceeventdetails string,
  sharedeventid string,
  vpcendpointid string,
  tlsdetails map<string,string>
)
COMMENT 'CloudTrail table for security audit'
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.containercustom.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://${aws_s3_bucket.central_logs.id}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/';
EOF
}