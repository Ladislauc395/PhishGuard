class UserModel {
  final int id;
  final String name;
  final String email;
  final String? avatarUrl;
  final String provider; // "local" | "google"

  const UserModel({
    required this.id,
    required this.name,
    required this.email,
    this.avatarUrl,
    required this.provider,
  });

  factory UserModel.fromJson(Map<String, dynamic> j) => UserModel(
        id: j['id'] as int,
        name: j['name'] as String,
        email: j['email'] as String,
        avatarUrl: j['avatar_url'] as String?,
        provider: j['provider'] as String? ?? 'local',
      );

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'email': email,
        'avatar_url': avatarUrl,
        'provider': provider,
      };

  bool get isGoogleUser => provider == 'google';
}
