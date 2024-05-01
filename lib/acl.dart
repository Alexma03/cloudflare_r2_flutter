enum ACL {
  /// Owner gets FULL_CONTROL. No one else has access rights (default).
  private,

  /// Owner gets FULL_CONTROL. The AllUsers group (see Who is a grantee?) gets READ access.
  publicRead,

  /// Owner gets FULL_CONTROL. The AllUsers group gets READ and WRITE access. Granting this on a bucket is generally not recommended.
  publicReadWrite,

  /// Owner gets FULL_CONTROL. Amazon EC2 gets READ access to GET an Amazon Machine Image (AMI) bundle from Amazon S3.
  awsExecRead,

  /// Owner gets FULL_CONTROL. The AuthenticatedUsers group gets READ access.
  authenticatedRead,

  /// Object owner gets FULL_CONTROL. Bucket owner gets READ access. If you specify this canned ACL when creating a bucket, Amazon S3 ignores it.
  bucketOwnerRead,

  /// Both the object owner and the bucket owner get FULL_CONTROL over the object. If you specify this canned ACL when creating a bucket, Amazon S3 ignores it.
  bucketOwnerFullControl,

  /// The LogDelivery group gets WRITE and READ_ACP permissions on the bucket. For more information about logs
  logDeliveryWrite,
}


String aclToString(ACL acl) {
  switch (acl) {
    case ACL.private:
      return 'private';
    case ACL.publicRead:
      return 'public-read';
    case ACL.publicReadWrite:
      return 'public-read-write';
    case ACL.awsExecRead:
      return 'aws-exec-read';
    case ACL.authenticatedRead:
      return 'authenticated-read';
    case ACL.bucketOwnerRead:
      return 'bucket-owner-read';
    case ACL.bucketOwnerFullControl:
      return 'bucket-owner-full-control';
    case ACL.logDeliveryWrite:
      return 'log-delivery-write';
  }
}