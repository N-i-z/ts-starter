import { Injectable, NotFoundException } from '@nestjs/common';
import { CreatePostDto } from './dto/createPost.dto';
import { UpdatePostDto } from './dto/updatePost.dto';
import Post from './post.entity'; // Assume you have an entity class Post

@Injectable()
export class PostsService {
  private posts: Post[] = []; // Simulated data storage for posts

  getAllPosts() {
    return this.posts;
  }

  getPostById(id: number): Post {
    const post = this.posts.find((post) => post.id === id);
    if (!post) {
      throw new NotFoundException('Post not found');
    }
    return post;
  }

  createPost(postData: CreatePostDto) {
    const newPost = { id: Date.now(), ...postData }; // Simulated ID generation
    this.posts.push(newPost);
    return newPost;
  }

  replacePost(id: number, postData: UpdatePostDto) {
    const postIndex = this.posts.findIndex((post) => post.id === id);
    if (postIndex === -1) {
      throw new NotFoundException('Post not found');
    }
    this.posts[postIndex] = { id, ...postData };
    return this.posts[postIndex];
  }

  updatePost(id: number, postData: UpdatePostDto) {
    const post = this.getPostById(id);
    Object.assign(post, postData); // Merge the partial update
    return post;
  }

  deletePost(id: number) {
    const postIndex = this.posts.findIndex((post) => post.id === id);
    if (postIndex === -1) {
      throw new NotFoundException('Post not found');
    }
    this.posts.splice(postIndex, 1);
  }
}
