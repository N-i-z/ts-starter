import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { Transform } from 'class-transformer';

@Entity()
class Post {
  @PrimaryGeneratedColumn()
  public id: number;

  @Column()
  public title?: string;

  @Column()
  public content?: string;

  @Column({ nullable: true })
  @Transform(({ value }: { value: any }) => {
    return value !== null ? value : undefined;
  })
  public category?: string;
}

export default Post;
