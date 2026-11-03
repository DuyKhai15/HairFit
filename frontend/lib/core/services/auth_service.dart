// ============================================================================
// File: lib/core/services/auth_service.dart
// Mục đích: Cung cấp dịch vụ hạ tầng (auth).
// Kết cấu:
//  - Xác thực qua Firebase Auth, đồng bộ hồ sơ người dùng qua ASP.NET API hoặc Cloud Firestore.
// ============================================================================

import 'dart:async';

import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';

import '../../models/user_model.dart';
import 'api_client.dart';

/// Exception khi tài khoản bị khóa
class BlockedAccountException implements Exception {
  final String message;
  const BlockedAccountException([
    this.message =
        'Tài khoản của bạn đã bị khóa. Vui lòng liên hệ quản trị viên.',
  ]);

  @override
  String toString() => message;
}

/// Exception chung cho Auth với thông báo thân thiện bằng tiếng Việt
class AuthException implements Exception {
  final String message;
  const AuthException(this.message);

  @override
  String toString() => message;
}

/// Service xử lý xác thực người dùng bằng Firebase Auth, ASP.NET Core Web API và Cloud Firestore
class AuthService {
  final FirebaseAuth _firebaseAuth;
  final FirebaseFirestore _firestore;
  final ApiClient _apiClient;

  AuthService({
    FirebaseAuth? firebaseAuth,
    FirebaseFirestore? firestore,
    ApiClient? apiClient,
  }) : _firebaseAuth = firebaseAuth ?? FirebaseAuth.instance,
       _firestore = firestore ?? FirebaseFirestore.instance,
       _apiClient = apiClient ?? ApiClient(firebaseAuth: firebaseAuth);

  /// Stream theo dõi trạng thái Authentication của Firebase
  Stream<User?> get authStateChanges => _firebaseAuth.authStateChanges();

  /// User hiện tại từ Firebase Auth
  User? get currentAuthUser => _firebaseAuth.currentUser;

  /// Đăng ký tài khoản mới bằng Email/Password (UC-01)
  Future<UserModel> register({
    required String email,
    required String password,
    required String displayName,
    required UserRole role,
  }) async {
    try {
      debugPrint(
        '🔑 [AuthService] Bắt đầu đăng ký: $email, role: ${role.toRoleString()}',
      );

      // 1. Tạo tài khoản trong Firebase Auth
      final credential = await _firebaseAuth.createUserWithEmailAndPassword(
        email: email.trim(),
        password: password,
      );

      final firebaseUser = credential.user;
      if (firebaseUser == null) {
        throw const AuthException(
          'Đăng ký không thành công. Vui lòng thử lại.',
        );
      }

      // 2. Cập nhật Display Name trong Firebase Auth
      await firebaseUser.updateDisplayName(displayName.trim());

      final now = DateTime.now();
      final userModel = UserModel(
        uid: firebaseUser.uid,
        email: email.trim(),
        displayName: displayName.trim(),
        avatarUrl: '',
        role: role,
        isBlocked: false,
        createdAt: now,
        updatedAt: now,
      );

      // 3. Lưu vào Cloud Firestore
      try {
        await _firestore
            .collection('users')
            .doc(firebaseUser.uid)
            .set(userModel.toMap());
      } catch (e) {
        debugPrint('⚠️ [AuthService] Lỗi lưu user Firestore: $e');
      }

      // 4. Thử đồng bộ lên ASP.NET Core Web API (nếu server online)
      try {
        await _apiClient.post(
          '/api/users/sync',
          body: {
            'uid': firebaseUser.uid,
            'email': email.trim(),
            'displayName': displayName.trim(),
            'role': role.toRoleString(),
            'avatarUrl': '',
          },
        ).timeout(const Duration(seconds: 2));
      } catch (e) {
        debugPrint(
          '⚠️ [AuthService] API sync timeout/offline ($e), tiếp tục dùng Firebase Auth/Firestore',
        );
      }

      return userModel;
    } on FirebaseAuthException catch (e) {
      debugPrint(
        '❌ [AuthService] FirebaseAuthException: ${e.code} - ${e.message}',
      );
      throw AuthException(_mapFirebaseError(e));
    } catch (e) {
      debugPrint('❌ [AuthService] Lỗi không xác định: $e');
      if (e is AuthException || e is BlockedAccountException) rethrow;
      throw AuthException('Đã xảy ra lỗi: ${e.toString()}');
    }
  }

  /// Đăng nhập tài khoản bằng Email/Password (UC-01)
  Future<UserModel> login({
    required String email,
    required String password,
  }) async {
    try {
      debugPrint('🔑 [AuthService] Đăng nhập: $email');

      // 1. Xác thực qua Firebase Auth
      final credential = await _firebaseAuth.signInWithEmailAndPassword(
        email: email.trim(),
        password: password,
      );

      final firebaseUser = credential.user;
      if (firebaseUser == null) {
        throw const AuthException('Đăng nhập thất bại. Vui lòng thử lại.');
      }

      UserModel? userModel;

      // 2. Thử lấy dữ liệu từ API (nếu online)
      try {
        final response = await _apiClient.post(
          '/api/users/sync',
          body: {
            'uid': firebaseUser.uid,
            'email': firebaseUser.email ?? email.trim(),
            'displayName':
                firebaseUser.displayName ?? email.trim().split('@').first,
          },
        ).timeout(const Duration(seconds: 2));

        if (response is Map) {
          userModel = UserModel.fromMap(
            Map<String, dynamic>.from(response),
            id: firebaseUser.uid,
          );
        }
      } catch (apiErr) {
        debugPrint(
          '⚠️ [AuthService] API sync offline/timeout ($apiErr), fallback Cloud Firestore...',
        );
      }

      // Fallback 1: Đọc từ Cloud Firestore
      if (userModel == null) {
        try {
          final userDoc = await _firestore
              .collection('users')
              .doc(firebaseUser.uid)
              .get();

          if (userDoc.exists) {
            userModel = UserModel.fromFirestore(userDoc);
          }
        } catch (fsErr) {
          debugPrint('⚠️ [AuthService] Firestore fetch error: $fsErr');
        }
      }

      // Fallback 2: Tự động khởi tạo UserModel dựa trên email & Firebase Auth
      userModel ??= UserModel(
        uid: firebaseUser.uid,
        email: firebaseUser.email ?? email.trim(),
        displayName:
            firebaseUser.displayName ?? email.trim().split('@').first,
        role: email.toLowerCase().contains('admin')
            ? UserRole.admin
            : (email.toLowerCase().contains('barber')
                ? UserRole.barber
                : UserRole.customer),
        isBlocked: false,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      // 3. Kiểm tra tài khoản có bị khóa không (isBlocked)
      if (userModel.isBlocked) {
        debugPrint(
          '🚫 [AuthService] Tài khoản ${userModel.uid} bị khóa. Buộc đăng xuất.',
        );
        await _firebaseAuth.signOut();
        throw const BlockedAccountException();
      }

      debugPrint(
        '✅ [AuthService] Đăng nhập thành công: ${userModel.displayName} (${userModel.role.toRoleString()})',
      );
      return userModel;
    } on FirebaseAuthException catch (e) {
      debugPrint(
        '❌ [AuthService] FirebaseAuthException: ${e.code} - ${e.message}',
      );
      throw AuthException(_mapFirebaseError(e));
    } on BlockedAccountException {
      rethrow;
    } catch (e) {
      debugPrint('❌ [AuthService] Login error: $e');
      if (e is AuthException) rethrow;
      throw AuthException('Đăng nhập thất bại: ${e.toString()}');
    }
  }

  /// Lấy thông tin UserModel hiện tại từ API hoặc Firestore
  Future<UserModel?> getCurrentUserModel() async {
    final authUser = _firebaseAuth.currentUser;
    if (authUser == null) return null;

    UserModel? userModel;

    // 1. Thử lấy từ API
    try {
      final response = await _apiClient
          .get('/api/users/${authUser.uid}')
          .timeout(const Duration(seconds: 2));

      if (response is Map) {
        userModel = UserModel.fromMap(
          Map<String, dynamic>.from(response),
          id: authUser.uid,
        );
      }
    } catch (_) {}

    // 2. Fallback: Lấy từ Cloud Firestore
    if (userModel == null) {
      try {
        final doc =
            await _firestore.collection('users').doc(authUser.uid).get();
        if (doc.exists) {
          userModel = UserModel.fromFirestore(doc);
        }
      } catch (_) {}
    }

    // 3. Fallback: Tự khởi tạo từ Firebase Auth
    userModel ??= UserModel(
      uid: authUser.uid,
      email: authUser.email ?? '',
      displayName:
          authUser.displayName ??
          (authUser.email?.split('@').first ?? 'Người dùng'),
      role: (authUser.email?.toLowerCase().contains('admin') ?? false)
          ? UserRole.admin
          : ((authUser.email?.toLowerCase().contains('barber') ?? false)
              ? UserRole.barber
              : UserRole.customer),
    );

    if (userModel.isBlocked) {
      await _firebaseAuth.signOut();
      throw const BlockedAccountException();
    }

    return userModel;
  }

  /// Gửi email đặt lại mật khẩu (UC-01)
  Future<void> sendPasswordResetEmail(String email) async {
    try {
      debugPrint('📧 [AuthService] Gửi email reset password tới: $email');
      await _firebaseAuth.sendPasswordResetEmail(email: email.trim());
      debugPrint('✅ [AuthService] Đã gửi email reset password');
    } on FirebaseAuthException catch (e) {
      debugPrint('❌ [AuthService] sendPasswordResetEmail error: ${e.code}');
      throw AuthException(_mapFirebaseError(e));
    } catch (e) {
      throw AuthException('Không thể gửi yêu cầu đặt lại mật khẩu: $e');
    }
  }

  /// Cập nhật thông tin hồ sơ người dùng (displayName, avatarUrl)
  Future<UserModel> updateUserProfile({
    required String uid,
    required String displayName,
    String? avatarUrl,
  }) async {
    try {
      debugPrint('👤 [AuthService] Cập nhật thông tin hồ sơ: $displayName');

      final authUser = _firebaseAuth.currentUser;
      if (authUser != null && authUser.uid == uid) {
        await authUser.updateDisplayName(displayName.trim());
      }

      // Cập nhật Firestore
      try {
        await _firestore.collection('users').doc(uid).update({
          'displayName': displayName.trim(),
          if (avatarUrl != null) 'avatarUrl': avatarUrl.trim(),
          'updatedAt': FieldValue.serverTimestamp(),
        });
      } catch (_) {}

      // Thử cập nhật API
      try {
        await _apiClient.put(
          '/api/users/$uid/profile',
          body: {
            'displayName': displayName.trim(),
            if (avatarUrl != null) 'avatarUrl': avatarUrl.trim(),
          },
        ).timeout(const Duration(seconds: 2));
      } catch (_) {}

      final doc = await _firestore.collection('users').doc(uid).get();
      if (doc.exists) {
        return UserModel.fromFirestore(doc);
      }

      return UserModel(
        uid: uid,
        email: authUser?.email ?? '',
        displayName: displayName.trim(),
        avatarUrl: avatarUrl?.trim() ?? '',
      );
    } catch (e) {
      debugPrint('❌ [AuthService] Lỗi cập nhật profile: $e');
      throw AuthException('Không thể cập nhật thông tin: $e');
    }
  }

  /// Lưu dáng khuôn mặt AI của khách hàng (Task Phase 3 - C2)
  Future<void> saveUserFaceShape(String uid, String faceShape) async {
    try {
      await _firestore.collection('users').doc(uid).update({
        'savedFaceShape': faceShape,
        'updatedAt': FieldValue.serverTimestamp(),
      });
    } catch (_) {}

    try {
      await _apiClient.put(
        '/api/users/$uid/face-shape',
        body: {'faceShape': faceShape},
      ).timeout(const Duration(seconds: 2));
    } catch (_) {}
  }

  /// Thêm hoặc bỏ thợ cắt tóc khỏi danh sách yêu thích (Task Phase 3 - C3)
  Future<List<String>> toggleFavoriteBarber(
    String uid,
    String barberId,
  ) async {
    try {
      final docRef = _firestore.collection('users').doc(uid);
      final doc = await docRef.get();
      final currentFavorites = List<String>.from(
        doc.data()?['favoriteBarberIds'] ?? [],
      );
      if (currentFavorites.contains(barberId)) {
        currentFavorites.remove(barberId);
        await docRef.update({
          'favoriteBarberIds': FieldValue.arrayRemove([barberId]),
          'updatedAt': FieldValue.serverTimestamp(),
        });
      } else {
        currentFavorites.add(barberId);
        await docRef.update({
          'favoriteBarberIds': FieldValue.arrayUnion([barberId]),
          'updatedAt': FieldValue.serverTimestamp(),
        });
      }

      try {
        await _apiClient.post(
          '/api/users/$uid/favorites/toggle',
          body: {'barberId': barberId},
        ).timeout(const Duration(seconds: 2));
      } catch (_) {}

      return currentFavorites;
    } catch (e) {
      debugPrint('⚠️ [AuthService] Lỗi toggle favorite barber: $e');
      return [];
    }
  }

  /// Đăng xuất khỏi hệ thống
  Future<void> logout() async {
    debugPrint('👋 [AuthService] Đăng xuất');
    await _firebaseAuth.signOut();
  }

  /// Chuyển đổi mã lỗi Firebase Auth sang thông báo tiếng Việt dễ hiểu
  String _mapFirebaseError(FirebaseAuthException e) {
    switch (e.code) {
      case 'user-not-found':
      case 'wrong-password':
      case 'invalid-credential':
        return 'Email hoặc mật khẩu không chính xác. Vui lòng kiểm tra lại.';
      case 'email-already-in-use':
        return 'Địa chỉ email này đã được đăng ký. Vui lòng đăng nhập hoặc dùng email khác.';
      case 'invalid-email':
        return 'Định dạng email không hợp lệ.';
      case 'weak-password':
        return 'Mật khẩu quá yếu. Vui lòng chọn mật khẩu có ít nhất 6 ký tự.';
      case 'user-disabled':
        return 'Tài khoản này đã bị vô hiệu hóa.';
      case 'too-many-requests':
        return 'Bạn đã thao tác sai quá nhiều lần. Vui lòng đợi trong giây lát và thử lại.';
      case 'network-request-failed':
        return 'Không thể kết nối Internet. Vui lòng kiểm tra kết nối mạng của bạn.';
      case 'operation-not-allowed':
        return 'Tính năng đăng nhập bằng email chưa được bật trên Firebase. Vui lòng bật Email/Password trong Firebase Console.';
      default:
        return e.message ?? 'Đã xảy ra lỗi xác thực. Vui lòng thử lại sau.';
    }
  }
}

// CreBy: MenBoyBMN
