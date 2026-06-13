import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { NextAuthOptions } from 'next-auth';
import dbConnect from './mongodb';
import NguoiDung from '@/models/NguoiDung';
import { compare } from 'bcryptjs';

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        matKhau: { label: 'Mật khẩu', type: 'password' }
      },
      async authorize(credentials) {
        // ĐỒNG BỘ TẠI ĐÂY: Nhận diện cả 'matKhau' và 'password' từ giao diện gửi lên
        const email = credentials?.email;
        const plainPassword = credentials?.matKhau || (credentials as any)?.password;

        if (!email || !plainPassword) {
          return null;
        }

        try {
          await dbConnect();
          
          const user = await NguoiDung.findOne({ 
            email: email.toLowerCase(),
            trangThai: 'hoatDong'
          }).select('+matKhau +password');

          if (!user) {
            return null;
          }

          // Đối chiếu mật khẩu trực tiếp vào cơ sở dữ liệu
          const isPasswordValid = await compare(plainPassword, user.password || user.matKhau);

          if (!isPasswordValid) {
            return null;
          }

          return {
            id: user._id.toString(),
            email: user.email,
            name: user.ten,
            role: user.vaiTro,
            phone: user.soDienThoai,
            avatar: user.anhDaiDien,
          };
        } catch (error) {
          console.error('Auth error:', error);
          return null;
        }
      }
    })
  ],
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.role = user.role;
        token.phone = user.phone;
        token.avatar = user.avatar;
      }
      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.sub!;
        session.user.role = token.role as string;
        session.user.phone = token.phone as string;
        session.user.avatar = token.avatar as string;
      }
      return session;
    }
  },
  pages: {
    signIn: '/dang-nhap',
    error: '/dang-nhap',
  },
  secret: process.env.NEXTAUTH_SECRET,
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
