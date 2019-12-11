"""empty message

Revision ID: 723053ec5e7e
Revises: 2c27e4d6785b
Create Date: 2019-11-16 11:09:49.665934

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '723053ec5e7e'
down_revision = '2c27e4d6785b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('posts', sa.Column('not_granted', sa.Boolean(), server_default=sa.text('1'), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('posts', 'not_granted')
    # ### end Alembic commands ###