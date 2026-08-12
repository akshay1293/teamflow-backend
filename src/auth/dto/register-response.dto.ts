export class RegisterResponseDto {
  id!: string;
  email!: string;
  emailVerifiedAt!: Date | null;
  createdAt!: Date;
}
