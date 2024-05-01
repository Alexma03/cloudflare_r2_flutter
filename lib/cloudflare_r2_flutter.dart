library cloudflare_r2_flutter;

import 'dart:io';

import 'package:amazon_cognito_identity_dart_2/sig_v4.dart';
import 'package:cloudflare_r2_flutter/acl.dart';
import 'package:cloudflare_r2_flutter/string_to_sign.dart';
import 'package:dio/dio.dart';
import 'package:recase/recase.dart';

/// A Calculator.
class CloudFlareR2 {
  final String accessKey;
  final String secretKey;
  final String userId;
  final String bucketId;
  String? region;
  final ACL acl;

  CloudFlareR2({
    required this.accessKey,
    required this.secretKey,
    required this.userId,
    required this.bucketId,
    this.region,
    this.acl = ACL.publicRead,
  });

  Future<String> uploadFile(
    File file,
    String contentType, {
    String? fileName,
    String? destDir,
    Map<String, String>? metadata,
  }) async {
    // Create the request URL
    final String finalUrl;
    if (region != null) {
      // If a region is provided, use it in the URL
      finalUrl = 'https://$userId.$region.r2.cloudflarestorage.com/$bucketId';
    } else {
      // If no region is provided, use the default URL and set the region to 'auto'
      finalUrl = 'https://$userId.r2.cloudflarestorage.com/$bucketId';
    }

    // Get the current date in the required format
    final datetime = SigV4.generateDatetime();

    // Create the final name of the file
    final finalFileName = fileName ?? file.path.split('/').last;

    // Create the final destination directory
    final finalDestDir =
        destDir == null ? finalFileName : '/$destDir/$finalFileName';

    // Add the final destination directory to the URL
    finalUrl + finalDestDir;

    // Length of the file
    final length = await file.length();

    // Convert metadata to query parameters
    final metadataParams = _convertMetadataToParams(metadata);

    // Create the form data
    final formData = FormData.fromMap({
      'file': await MultipartFile.fromFile(file.path, filename: fileName),
    });

    // Create SignIngKey
    final signingKey =
        SigV4.calculateSigningKey(secretKey, datetime, region!, 's3');

    // Generate Policy
    final Policy policy;
    if (region != null) {
      policy = Policy.fromS3PresignedPost(
        finalDestDir,
        bucketId,
        accessKey,
        15,
        length,
        acl,
        region: region!,
        metadata: metadataParams,
      );
    } else {
      policy = Policy.fromS3PresignedPost(
        finalDestDir,
        bucketId,
        accessKey,
        15,
        length,
        acl,
        metadata: metadataParams,
      );
    }

    // Create signature
    final signature = SigV4.calculateSignature(signingKey, policy.encode());

    // Create the request headers
    final headers = {
      'key': finalDestDir,
      'acl': aclToString(acl),
      'X-Amz-Credential': policy.credential,
      'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
      'X-Amz-Date': policy.datetime,
      'Policy': policy.encode(),
      'X-Amz-Signature': signature,
      'Content-Type': contentType
    };

    // If metadata is provided, add it to the headers
    if (metadata != null) {
      headers.addAll(metadataParams);
    }

    // Create the Dio instance
    final dio = Dio();

    // Send the request
    try {
      await dio.post(
        finalUrl,
        data: formData,
        options: Options(
          headers: headers,
        ),
      );

      return finalUrl;
    } catch (e) {
      throw Exception('Error uploading image to Cloudflare R2 ${e.toString()}');
    }
  }

  static Map<String, String> _convertMetadataToParams(
      Map<String, String>? metadata) {
    Map<String, String> updatedMetadata = {};

    if (metadata != null) {
      for (var k in metadata.keys) {
        updatedMetadata['x-amz-meta-${k.paramCase}'] = metadata[k]!;
      }
    }

    return updatedMetadata;
  }
}
