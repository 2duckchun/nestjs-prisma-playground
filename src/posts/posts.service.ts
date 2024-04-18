import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { CreatePostDto } from './dto';

@Injectable()
export class PostsService {
  constructor(private prisma: PrismaService) {}

  async create(createPostDto: CreatePostDto) {
    return this.prisma.post.create({
      data: {
        title: createPostDto.title,
        content: createPostDto.content,
        authorId: +createPostDto.authorId,
      },
    });
  }

  findAll() {
    return this.prisma.post.findMany({
      include: {
        author: {
          select: {
            email: true,
            name: true,
          },
        },
      },
    });
  }
}
