import '../core/api_client.dart';
import '../models/analyze_response.dart';

class AnalyzeService {
  final ApiClient api;
  AnalyzeService({ApiClient? api}) : api = api ?? ApiClient();

  Future<AnalyzeResponse> analyzeUrl(String url) async {
    final j = await api.post('/analyze/url', {'url': url});
    return AnalyzeResponse.fromJson(j);
  }

  Future<AnalyzeResponse> analyzeSms(String body, {String? phoneNumber}) async {
    final j = await api.post('/analyze/sms', {
      'body': body,
      if (phoneNumber != null) 'phone_number': phoneNumber,
      // compat com main.py
      'message': body,
      'sender': phoneNumber ?? '',
    });
    return AnalyzeResponse.fromJson(j);
  }

  Future<AnalyzeResponse> analyzeEmail({
    required String sender,
    required String headers,
    String? subject,
    String? body,
  }) async {
    final j = await api.post('/analyze/email', {
      'sender': sender,
      'headers': headers,
      'raw_headers': headers,
      if (subject != null) 'subject': subject,
      if (body != null) 'body': body,
    });
    return AnalyzeResponse.fromJson(j);
  }
}
