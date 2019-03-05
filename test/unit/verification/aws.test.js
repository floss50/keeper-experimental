/* aws js sdk & settings */
var AWS = require('aws-sdk');
AWS.config.update({region: 'us-east-1'});
s3 = new AWS.S3({apiVersion: '2006-03-01'});

var params = {
  Bucket: "spectrexps",
  Key: "data.csv"
 };

 s3.headObject(params, function(err, data) {
  if (err){
    console.log(err, err.stack); // an error occurred
  } else {
    console.log("etag : " + data.ETag);           // successful response
  }
});
