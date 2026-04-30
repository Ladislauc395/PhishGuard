import '../core/api_client.dart';
import '../models/stats_response.dart';

class DashboardService {
  final ApiClient api;
  DashboardService({ApiClient? api}) : api = api ?? ApiClient();

  Future<StatsResponse> getStats() async {
    final j = await api.get('/dashboard/stats');
    return StatsResponse.fromJson(j);
  }
}
